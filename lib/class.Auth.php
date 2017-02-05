<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Adapted for CMSMS from PHPAuth <https://www.phpclasses.org/package/9887-PHP-Register-and-publicid-users-stored-in-a-database.html>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
# Requires PHP 5.4+
#----------------------------------------------------------------------
namespace Auther;

/* TODO
2FA support
 captcha?

addUser() race fix
generic autoloading
send events  $this->mod->SendEvent('OnX',$parms);
*/

include __DIR__.DIRECTORY_SEPARATOR.'password.php';

class Auth extends Session
{
	const EMAILPATN = '/^.+@.+\..+$/';
	const STRETCHES = 12; //hence 2**12

	public function __construct(&$mod, $context=NULL)
	{
		parent::__construct($mod, $context);
	}

	/**
	* Logs a user in
	* @publicid: string user identifier
	* @password: plaintext string
	* @nonce: default = FALSE
	* @remember: boolean whether to setup session-expiry-time in self::AddSession() default = FALSE
	* Returns: array, 0=>T/F for success, 1=>message, if success then also session-parameters: 'token','expire'
	*/
	public function login($publicid, $password, $nonce=FALSE, $remember=FALSE)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				$this->mod->SendEvent('OnLoginFail', $parms);
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$uid = $this->getUID($publicid);

		if (!$uid) {
			$this->AddAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('login_incorrect')];
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata['active']) {
			$this->AddAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('account_inactive')];
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->AddAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		if (!is_bool($remember)) {
			$this->AddAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('remember_me_invalid')];
		}

		$sessiondata = $this->AddSession($uid, $remember);

		if (!$sessiondata) {
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('system_error').' #01'];
		}

		$this->mod->SendEvent('OnLogin', $parms);

		$data = [TRUE,$this->mod->Lang('logged_in')];
		$data['token'] = $sessiondata['token'];
		$data['expire'] = $sessiondata['expiretime'];
		return $data;
	}

	/**
	* Creates and records a user
	* @publicid: string user identifier
	* @password: plaintext string
	* @repeatpassword: plaintext string
	* @email: email address for notices to the user default = ''
	* @params: array extra user-parameters for self::addUser() default = empty
	* @sendmail: bool whether to send email-messages if possible default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function register($publicid, $password, $repeatpassword, $email='', $params=[], $sendmail=NULL)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		// Validate publicid
		$status = $this->validateLogin($publicid);
		if (!$status[0]) {
			return $status;
		}

		if ($this->isLoginTaken($publicid)) {
			return [FALSE,$this->mod->Lang('login_taken')];
		}

		// Validate password
		$status = $this->validatePassword($password);
		if (!$status[0]) {
			return $status;
		}

		if ($password !== $repeatpassword) {
			return [FALSE,$this->mod->Lang('password_nomatch')];
		}

		if ($email) {
			// Validate email
			$status = $this->validateEmail($email);
			if (!$status[0]) {
				return $status;
			}
		}

		$status = $this->addUser($publicid, $password, $email, $sendmail, $params);
		if (!$status[0]) {
			return $status;
		}

		$this->mod->SendEvent('OnRegister', $parms);

		$msg = ($sendmail) ?
		 $this->mod->Lang('register_success') :
		 $this->mod->Lang('register_success_message_suppressed');
		return [TRUE,$msg];
	}

	/**
	* Activates a user's account
	* @key: string 32-byte token
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function activate($key)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		if (strlen($key) !== 32) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('activationkey_invalid')];
		}

		$data = $this->getRequest($key, 'activate');

		if (!$data[0]) {
			$this->AddAttempt();
			return $data;
		}

		$userdata = $this->getBaseUser($data['uid']);
		if ($userdata['active']) {
			$this->AddAttempt();
			$this->deleteRequest($data['id']);
			return [FALSE,$this->mod->Lang('system_error').' #02'];
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET active=1 WHERE id=?';
		$this->db->Execute($sql, [$data['uid']]);

		$this->deleteRequest($data['id']);

		return [TRUE,$this->mod->Lang('account_activated')];
	}

	/**
	* Creates a reset-key for @publicid and sends email
	* @publicid: string user identifier
	* @sendmail: boolean whether to send confirmation email default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function requestReset($publicid, $sendmail=NULL)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$status = $this->validateLogin($publicid);

		if (!$status[0]) {
			//TODO minimise impact of $publicid brute-forcing
			return [FALSE,$this->mod->Lang('login_invalid')];
		}

		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=?';
		$id = $this->db->GetOne($sql, [$publicid]);

		if (!$id) {
			//TODO minimise impact of $publicid brute-forcing
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('login_incorrect')];
		}

		$status = $this->addRequest($id, $publicid, 'reset', $sendmail);

		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		$msg = ($sendmail) ?
		 $this->mod->Lang('reset_requested') :
		 $this->mod->Lang('reset_requested_loginmessage_suppressed');
		return [TRUE,$msg];
	}

	/**
	* Ends the session identified by @token
	* @token: string 24-byte session-identifier
	* Returns: boolean
	*/
	public function logout($token)
	{
		if (strlen($token) != 24) {
			return FALSE;
		}
		return $this->DeleteSession($token);
	}

	/**
	* Changes recorded context property
	* @context: numeric identifier or alias for login context
	*/
	public function setContext($context)
	{
		$this->context = $context;
	}

	/**
	* Gets user-enumerator for @publicid (whether or not currently active)
	* @publicid: string user identifier
	* Returns: user enumerator
	*/
	public function getUID($publicid)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id';
		if ($this->context !== NULL) {
			$sql .= '=?';
			$args = [$publicid, $this->context];
		} else {
			$sql .= ' IS NULL';
			$args = [$publicid];
		}
		return $this->db->GetOne($sql, $args);
	}

	/**
	* Method for preventing duplicates and user-recognition checks
	* Checks whether @publicid is recorded for current context
	* @publicid: string user identifier
	* Returns: boolean
	*/
	public function isLoginTaken($publicid)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id';
		if ($this->context !== NULL) {
			$sql .= '=?';
			$args = [$publicid, $this->context];
		} else {
			$sql .= ' IS NULL';
			$args = [$publicid];
		}
		$num = $this->db->GetOne($sql, $args);
		return ($num > 0);
	}

	/**
	* Records a new user
	* @publicid: string user identifier
	* @password: plaintext string
	* @name: string user name
	* @address: email or other type of address for messages, possibly empty
	* @sendmail:  reference to boolean whether to send confirmation email messages
	* @params: array of additional params default = empty
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function addUser($publicid, $password, $name, $address, &$sendmail, $params=[])
	{
		$uid = $this->db->GenID($this->pref.'module_auth_users_seq');
		$publicid = htmlentities($publicid); //TODO encoding management

		if ($sendmail) { //TODO
			$status = $this->addRequest($uid, $publicid, 'activate', $sendmail);

			if (!$status[0]) {
				return $status;
			}

			$isactive = 0;
		} else {
			$isactive = 1;
		}

		$funcs = new Auther\Crypter();
		$password = password_hash($password, PASSWORD_DEFAULT);

		if ($name || is_numeric($name)) {
			$name = $funcs->encrypt_value($this->mod, $name);
		} else {
			$name = NULL;
		}
		if ($address || is_numeric($address)) {
			$address = $funcs->encrypt_value($this->mod, $address);
		} else {
			$address = NULL;
		}
		//TODO any others?
		$sql = 'INSERT INTO '.$this->pref.'module_auth_users (id,publicid,privhash,name,address,context_id,active) VALUES (?,?,?,?,?,?,?)';

		if (!$this->db->Execute($sql, [$uid, $publicid, $password, $name, $address, $this->context, $isactive])) {
			$this->deleteRequest($status[$TODO]);
			return [FALSE,$this->mod->Lang('system_error').' #03'];
		}

		if (is_array($params) && count($params) > 0) { //TODO
		}

		return [TRUE, ''];
	}

	/**
	* Gets basic user-data for the given UID
	* @uid: int user enumerator
	* Returns: array with members uid,publicid,privhash,active or else FALSE
	*/
	protected function getBaseUser($uid)
	{
		$sql = 'SELECT publicid,privhash,active FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql, [$uid]);

		if ($data) {
			$data['uid'] = $uid;
			return $data;
		}
		return FALSE;
	}

	/**
	* Gets all user-data except password for the given UID
	* @uid: int user enumerator
	* @raw: whether to decrypt relevant values, default = FALSE
	* Returns: array with members uid,publicid,name,address,context_id,addwhen,lastuse,nameswap,active or else FALSE
	*/
	public function getUser($uid, $raw = FALSE)
	{
		$sql = 'SELECT * FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql, [$uid]);

		if ($data) {
			unset($data['id']);
			unset($data['privhash']);
			if (!$raw) {
				$funcs = new Auther\Crypter();
				$data['name'] = $funcs->decrypt_value($this->mod, $data['name']);
				$data['address'] = $funcs->decrypt_value($this->mod, $data['address']);
//TODO context
//TODO zone offset
				$dt = new \DateTime('@0',NULL);
				$dt->setTimestamp($data['addwhen']);
				$data['addwhen'] = $dt->format('Y-m-d H:i:s');
				$dt->setTimestamp($data['lastuse']);
				$data['lastuse'] = $dt->format('Y-m-d H:i:s');
			}

			$data['uid'] = $uid; //=data['id']
			return $data;
		}
		return FALSE;
	}

	/**
	* Gets publicly-accessible user-data for @publicid
	* @publicid: string user identifier
	* @active: optional boolean whether the user is required to be active default = TRUE
	* Returns: array with members publicid,name,address,addwhen,lastuse or else FALSE
	*/
	public function getPublicUser($publicid, $active=TRUE)
	{
		$sql = 'SELECT name,address,addwhen,lastuse FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id';
		if ($this->context !== NULL) {
			$sql .= '=?';
			$args = [$publicid, $this->context];
		} else {
			$sql .= ' IS NULL';
			$args = [$publicid];
		}
		if ($active) {
			$sql .= ' AND active>0';
		}
		$data = $this->db->GetRow($sql, $args);

		if ($data) {
			$funcs = new Auther\Crypter();
			$data['name'] = $funcs->decrypt_value($this->mod, $data['name']);
			$data['address'] = $funcs->decrypt_value($this->mod, $data['address']);
//TODO zone offset
			$dt = new \DateTime('@0',NULL);
			$dt->setTimestamp($data['addwhen']);
			$data['addwhen'] = $dt->format('Y-m-d H:i:s');
			$dt->setTimestamp($data['lastuse']);
			$data['lastuse'] = $dt->format('Y-m-d H:i:s');
			$data['publicid'] = $publicid;
			return $data;
		}
		return FALSE;
	}

	/**
	* Deletes a user's data (aka account)
	* @uid: int user enumerator
	* @password: string plaintext
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function deleteUser($uid, $password)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang(TODO)];
		}

		if (!$this->password_check($password, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_users WHERE id=?';

		if (!$this->db->Execute($sql, [$uid])) {
			return [FALSE,$this->mod->Lang('system_error').' #05'];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE user_id=?';

		if (!$this->db->Execute($sql, [$uid])) {
			return [FALSE,$this->mod->Lang('system_error').' #06'];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_requests WHERE user_id=?';

		if (!$this->db->Execute($sql, [$uid])) {
			return [FALSE,$this->mod->Lang('system_error').' #07'];
		}

		$this->mod->SendEvent('OnDeregister', $parms);

		return [TRUE,$this->mod->Lang('account_deleted')];
	}

	/**
	* Gets data for all users for current context
	* Returns: associative array each of which is uid=>publicid, or FALSE
	*/
	public function getActiveUsers()
	{
		$sql = 'SELECT id,publicid FROM '.$this->pref.'module_auth_users WHERE context_id';
		if ($this->context !== NULL) {
			$sql .= '=?';
			$args = [$this->context];
		} else {
			$sql .= ' IS NULL';
			$args = [];
		}
		$sql .= ' AND active>0 ORDER BY addwhen';
		return $this->db->GetAssoc($sql, $args);
	}

	/**
	* Checks whether @publicid is recorded for current context and active, and @password is valid
	* @publicid: string user identifier
	* @password: plaintext string, or FALSE to skip password-validation
	* @active: optional boolean whether to check for active user, default TRUE
	* @fast: optional boolean whether to return immediately if not recognized, default FALSE
	* Returns: boolean
	*/
	public function isRegistered($publicid, $password, $active=TRUE, $fast=FALSE)
	{
		$sql = 'SELECT privhash,active FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id';
		if ($this->context !== NULL) {
			$sql .= '=?';
			$userdata = $this->db->GetRow($sql, [$publicid, $this->context]);
		} else {
			$sql .= ' IS NULL';
			$userdata = $this->db->GetRow($sql, [$publicid]);
		}
		if ($userdata && (!$active || $userdata['active'] > 0)) {
			if ($password === FALSE) {
				return TRUE;
			}
			$tries = ($fast) ? 0:1; //TODO $tries from session data
			return $this->password_check($password, $userdata['privhash'], $tries);
		}
		if (!$fast) {
			usleep(500000); //TODO $tries from session data
		}
		return FALSE;
	}

	/**
	* Creates an activation entry and sends publicid to user
	* @uid: int user enumerator
	* @publicid: string user identifier
	* @type: string 'reset' or 'activate'
	* @sendmail: boolean reference whether to send confirmation email
	* @fake: boolean whether to treat this as a bogus notice default = FALSE
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function addRequest($uid, $publicid, $type, &$sendmail, $fake=FALSE)
	{
		if (!($type == 'activate' || $type == 'reset')) {
			return [FALSE,$this->mod->Lang('system_error').' #08'];
		}

		// if not set manually, check config data
		if ($sendmail === NULL) {
			$sendmail = TRUE;
			if ($type == 'reset') {
				$val = $this->GetConfig('send_reset_message');
				if (!$val) {
					$sendmail = FALSE;
					return [TRUE,''];
				}
			} elseif ($type == 'activate') {
				$val = $this->GetConfig('send_activate_message');
				if (!$val) {
					$sendmail = FALSE;
					return [TRUE,''];
				}
			}
		}

		$sql = 'SELECT id,expire FROM '.$this->pref.'module_auth_requests WHERE user_id=? AND type=?';
		$row = $this->db->GetRow($sql, [$uid, $type]);

		if ($row) {
			if ($row['expire'] > time()) {
				return [FALSE,$this->mod->Lang('reset_exists')];
			}
			$this->deleteRequest($row['id']);
		}

		if ($type == 'activate') {
			$userdata = $this->getBaseUser($uid);
			if ($userdata['active']) {
				return [FALSE,$this->mod->Lang('already_activated')];
			}
		}

		$dt = new \DateTime('@'.time(), NULL);
		$val = $this->GetConfig('request_key_expiration');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$key = $this->UniqueToken(32);

		$request_id = $this->db->GenID($this->pref.'module_auth_requests_seq');

		if (!$fake) {
			$sql = 'INSERT INTO '.$this->pref.'module_auth_requests (id,user_id,expire,rkey,type) VALUES (?,?,?,?,?)';

			if (!$this->db->Execute($sql, [$request_id, $uid, $expiretime, $key, $type])) {
				return [FALSE,$this->mod->Lang('system_error').' #09'];
			}
		}

		if (!$sendmail) {
			return [TRUE,$this->mod->Lang('X')]; //TODO no email sent
		}

		if ($this->mod->before20) {
			$mlr = \cms_utils::get_module('CMSMailer');
			if ($mlr) {
				$mlr->_load();
			} else {
				$sendmail = FALSE;
				$this->deleteRequest($request_id);
				return [FALSE,$this->mod->Lang('system_error').' CMSMailer N/A'];
			}
		} else {
			$mlr = new \cms_mailer();
		}

		$site_name = $this->GetConfig('context_sender'); //TODO this gets a personal name

		$mlr->reset();
		if (1) { //TODO default sender isn't wanted
			$site_from = $this->GetConfig('context_address');
			$mlr->SetFrom($site_from, $site_name);
		}
		$mlr->AddAddress($email, '');

		$mlr->IsHTML(TRUE);

		//construct frontend-url (so no admin publicid is needed)
		$u = $this->mod->create_url('cntnt01', 'validate', '', [
				'cauthc'=>$key,
				'rauthr'=>$request_id]);
		$url = strtr($u, '&amp;', '&');

		if ($type == 'activate') {
			$mlr->SetSubject($this->mod->Lang('email_activation_subject', $site_name));
			$mlr->SetBody($this->mod->Lang('email_activation_body', $url, $site_name));
			$mlr->SetAltBody($this->mod->Lang('email_activation_altbody', $url, $site_name));
		} else { //reset
			$mlr->SetSubject($this->mod->Lang('email_reset_subject', $site_name));
			$mlr->SetBody($this->mod->Lang('email_reset_body', $url, $site_name));
			$mlr->SetAltBody($this->mod->Lang('email_reset_altbody', $url, $site_name));
		}

		$res = $mlr->Send();
		$msg = ($res) ? '' : $mlr->GetErrorInfo();
		$mlr->reset();

		if (!$res) {
			$this->deleteRequest($request_id);
		}
		return [$res, $msg];
	}

	/**
	* Returns request data if @key is valid
	* @key: 32-byte string from UniqueToken()
	* @type: string 'reset' or 'activate'
	* Returns: array 0=>T/F for success, 1=>message, if success then also 'id','uid'
	*/
	public function getRequest($key, $type)
	{
		$sql = 'SELECT id,user_id,expire FROM '.$this->pref.'module_auth_requests WHERE rkey=? AND type=?';
		$row = $this->db->GetRow($sql, [$key, $type]);

		if (!$row) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang($type.'key_incorrect')];
		}

		if ($row['expire'] < time()) {
			$this->AddAttempt();
			$this->deleteRequest($row['id']);
			return [FALSE,$this->mod->Lang($type.'key_expired')];
		}

		return [0=>TRUE,1=>'','id'=>$row['id'],'uid'=>$row['uid']];
	}

	/**
	* Deletes request from database
	* @id: int request enumerator
	* Returns: boolean
	*/
	protected function deleteRequest($id)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_requests WHERE id=?';
		$res = $this->db->Execute($sql, [$id]);
		return ($res != FALSE);
	}

	/**
	* Verifies that @publicid is an acceptable login identifier
	* @publicid: string user identifier
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function validateLogin($publicid)
	{
		$val = (int)$this->GetConfig('login_min_length');
		if ($val > 0 && strlen($publicid) < $val) {
			return [FALSE,$this->mod->Lang('login_short')];
		}

		$val = (int)$this->GetConfig('login_max_length');
		if ($val > 0 && strlen($publicid) > $val) {
			return [FALSE,$this->mod->Lang('login_long')];
		}

		if (preg_match(self::EMAILPATN, $publicid)) {
			$val = $this->GetConfig('email_banlist');
			if ($val) {
				$parts = explode('@', $publicid);
				$bannedDomains = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
				if (in_array(strtolower($parts[1]), $bannedDomains)) {
					return [FALSE,$this->mod->Lang('email_banned')];
				}
			}
		}
		//TODO duplication check
		return [TRUE,''];
	}

	/**
	* Verifies that @address is an acceptable contact address
	* @address: string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function validateAddress($address)
	{
		$val = $this->GetConfig('address_required');
		if ($val && !$address) {
			return [FALSE, $this->mod->Lang('missing_address')];
		}
		$val = $this->GetConfig('email_required');
		if ($val) {
			return $this->validateEmail($address);
		}
		return [TRUE,''];
	}

	/**
	* Verifies that @email is an acceptable email address
	* @email: string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function validateEmail($email)
	{
		if (!$email || !preg_match(self::EMAILPATN, $email)) {
			return [FALSE,$this->mod->Lang('email_invalid')];
		}
		//always check for ban
		$parts = explode('@', $email);
		$bannedDomains = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
		if (in_array(strtolower($parts[1]), $bannedDomains)) {
			return [FALSE,$this->mod->Lang('email_banned')];
		}
		return [TRUE,''];
	}

	/**
	* Verifies that @password is valid
	* @uid: int user enumerator
	* @password: plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function matchPassword($uid, $password)
	{
		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			return [FALSE,$this->mod->Lang('system_error').' #11'];
		}

		if (!$this->password_check($password, $userdata['password']/*, $tries TODO*/)) {
			return [FALSE,$this->mod->Lang('password_notvalid')];
		}
		return [TRUE,''];
	}

	/**
	* Verifies that @password respects security requirements
	* @password: plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function validatePassword($password)
	{
		$val = (int)$this->GetConfig('password_min_length');
		if ($val > 0 && strlen($password) < $val) {
			return [FALSE,$this->mod->Lang('password_short')];
		}
		//NB once-only else crash
		require_once __DIR__.DIRECTORY_SEPARATOR.'ZxcvbnPhp'.DIRECTORY_SEPARATOR.'Zxcvbn.php';
		$funcs = new \ZxcvbnPhp\Zxcvbn();
		$check = $funcs->passwordStrength($password);

		$val = (int)$this->GetConfig('password_min_score');
		if ($check['score'] + 1 < $val) { //returned value 0..4, public uses 1..5
			return [FALSE,$this->mod->Lang('password_weak')];
		}

		return [TRUE,''];
	}

	/**
	* Allows a user to reset her/his password after requesting a reset
	* @key: string 32-byte token
	* @password: plaintext string
	* @repeatpassword: plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function resetPassword($key, $password, $repeatpassword)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		if (strlen($key) != 32) {
			return [FALSE,$this->mod->Lang('resetkey_invalid')];
		}

		$data = $this->getRequest($key, 'reset');

		if (!$data[0]) {
			return $data;
		}

		$status = $this->matchPassword($data['uid'], $password);

		if (!$status[0]) {
			return $status;
		}

		if ($password !== $repeatpassword) {
			// Passwords don't match
			return [FALSE,$this->mod->Lang('newpassword_nomatch')];
		}

		$userdata = $this->getBaseUser($data['uid']);

		if (!$userdata) {
			$this->AddAttempt();
			$this->deleteRequest($data['id']);
			return [FALSE,$this->mod->Lang('system_error').' #11'];
		}

		if ($this->password_check($password, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('newpassword_match')];
		}

		$password = password_hash($password, PASSWORD_DEFAULT);
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET privhash=? WHERE id=?';
		$res = $this->db->Execute($sql, [$password, $data['uid']]);

		if ($res) {
			$this->deleteRequest($data['id']);
			return [TRUE,$this->mod->Lang('password_reset')];
		}
		return [FALSE,$this->mod->Lang('system_error').' #12'];
	}

	/**
	* Changes a user's password
	* @uid: int user enumerator
	* @currpass: plaintext string
	* @newpass: plaintext string
	* @repeatnewpass: plaintext string
	* Returns: array 0->T/F, 1=>message
	*/
	public function changePassword($uid, $currpass, $newpass, $repeatnewpass)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$status = $this->matchPassword($uid, $currpass);

		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		$status = $this->validatePassword($newpass);

		if (!$status[0]) {
			return $status;
		} elseif ($newpass !== $repeatnewpass) {
			return [FALSE,$this->mod->Lang('newpassword_nomatch')];
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('system_error').' #13'];
		}

		if (!$this->password_check($currpass, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		$newpass = password_hash($newpass, PASSWORD_DEFAULT);

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET privhash=? WHERE id=?';
		$this->db->Execute($sql, [$newpass, $uid]);
		return [TRUE,$this->mod->Lang('password_changed')];
	}

	/**
	* Compare user's password with given password
	* @uid: int user enumerator
	* @password_for_check: string
	* Returns: boolean indicating match
	*/
	public function comparePasswords($uid, $password_for_check)
	{
		$sql = 'SELECT privhash FROM '.$this->pref.'module_auth_users WHERE id=?';
		$password = $this->db->GetOne($sql, [$uid]);

		if ($password) {
			return $this->password_check($password_for_check, $password, 0);
		}
		return FALSE;
	}

	/**
	* Changes a user's publicid name
	* @uid: int user enumerator
	* @publicid: string user identifier
	* @password: plaintext string
	* Returns: array 0=>T/F, 1=>message
	*/
	public function changelogin($uid, $publicid, $password)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$status = $this->validateLogin($publicid);

		if (!$status[0]) {
			return $status;
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('system_error').' #14'];
		}

		if (!$this->password_check($password, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		if ($publicid == $userdata['publicid']) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('newlogin_match')];
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET publicid=? WHERE id=?';
		$res = $this->db->Execute($sql, [$publicid, $uid]);

		if ($res == FALSE) {
			return [FALSE,$this->mod->Lang('system_error').' #15'];
		}

		return [TRUE,$this->mod->Lang('login_changed')];
	}

	/**
	* Recreates activation email for @publicid and sends that email
	* @publicid: string user identifier
	* @sendmail: default = NULL  whether to send email notice
	* Returns: array 0=>T/F, 1=>message
	*/
	public function resendActivation($publicid, $sendmail=NULL)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		if ($sendmail == NULL) {
			return [FALSE,$this->mod->Lang('function_disabled')];
		}

		$status = $this->validateLogin($publicid);

		if (!$status[0]) {
			return $status;
		}

		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id';
		if ($this->context !== NULL) {
			$sql .= '=?';
			$args= [$publicid, $this->context];
		} else {
			$sql .= ' IS NULL';
			$args= [$publicid];
		}
		$id = $this->db->GetOne($sql, $args);

		if ($id == FALSE) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('login_incorrect')];
		}

		$userdata = $this->getBaseUser($id);

		if ($userdata['active']) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('already_activated')];
		}

		$status = $this->addRequest($id, $publicid, 'activate', $sendmail);

		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		return [TRUE,$this->mod->Lang('activation_sent')];
	}

	/**
	* Checks whether a user is logged in
	* Returns: boolean
	*/
	public function isLogged()
	{
		//TODO review http://php.net/manual/en/features.cookies.php &
		// http://php.net/manual/en/function.setcookie.php &
		// http://www.faqs.org/rfcs/rfc6265.html
		$val = $this->GetConfig('cookie_name');
		return (isset($_COOKIE[$val]) && $this->CheckSession($_COOKIE[$val]));
	}

	/**
	password_check:
	Verify @passwd against @hash

	@passwd: string The password to verify
	@hash: string The hash to verify against
	@tries: no. of verification attempts, may be 0 in which case immediate return on mismatch

	Returns: boolean Whether @passwd matches @hash
	*/
	protected function password_check($passwd, $hash, $tries=1)
	{
		if (password_verify($passwd, $hash)) {
			return TRUE;
		}
		$t = min(2000, $tries * 500);
		if ($t > 0) {
			usleep($t * 1000);
		}
		return FALSE;
	}

	/*
	bytelen:
	Count the number of bytes in @binary_string

	Vanilla strlen() might be shadowed by the mbstring extension,
	in which case strlen() will count the number of characters
	per the internal encoding, which count may be < the wanted number.

	@binary_string: string The input string

	Returns: int The number of bytes
	*/
	private function bytelen($binary_string)
	{
		if (function_exists('mb_strlen')) {
			return mb_strlen($binary_string, '8bit');
		}
		return strlen($binary_string);
	}
}
