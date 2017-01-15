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
send events	$this->mod->SendEvent('OnX',$parms);
*/

class Auth
{
	const EMAILPATN = '/^.+@.+\..+$/';
	const KEYSALT = 19; //prefix-length 19 + uniqid() 13, hence 32-byte session-key

	protected $mod;
	protected $db;
	protected $pref;
	protected $context;

	public function __construct(&$mod, $context=NULL)
	{
		$this->mod = $mod;
		$this->db = \cmsms()->GetDb();
		$tnis->pref = \cms_db_prefix();
		$this->context = $context;

		if (version_compare(phpversion(), '5.5.0', '<')) {
			require(__DIR__.DIRECTORY_SEPARATOR.'password.php');
		}
	}

	/**
	* Logs a user in
	* @publicid string user identifier
	* @password plaintext string
	* @nonce default = FALSE
	* @remember boolean whether to setup session-expiry-time in self::addSession() default = FALSE
	* Returns: array, 0=>T/F for success, 1=>message, if success then also session-parameters: 'hash','expire'
	*/
	public function login($publicid, $password, $nonce=FALSE, $remember=FALSE)
	{
		$block_status = $this->isBlocked();

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
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('login_incorrect')];
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata['active']) {
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('account_inactive')];
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		if (!is_bool($remember)) {
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('remember_me_invalid')];
		}

		$sessiondata = $this->addSession($uid, $remember);

		if (!$sessiondata) {
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('system_error').' #01'];
		}

		$this->mod->SendEvent('OnLogin', $parms);

		$data = [TRUE,$this->mod->Lang('logged_in')];
		$data['hash'] = $sessiondata['hash'];
		$data['expire'] = $sessiondata['expiretime'];
		return $data;
	}

	/**
	* Creates and records a user
	* @publicid string user identifier
	* @password plaintext string
	* @repeatpassword plaintext string
	* @email email address for notices to the user default = ''
	* @params array extra user-parameters for self::addUser() default = empty
	* @sendmail bool whether to send email-messages if possible default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function register($publicid, $password, $repeatpassword, $email='', $params=[], $sendmail=NULL)
	{
		$block_status = $this->isBlocked();

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
	* @key string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function activate($key)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		if (strlen($key) !== 32) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('activationkey_invalid')];
		}

		$data = $this->getRequest($key, 'activate');

		if (!$data[0]) {
			$this->addAttempt();
			return $data;
		}

		$userdata = $this->getBaseUser($data['uid']);
		if ($userdata['active']) {
			$this->addAttempt();
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
	* @publicid string user identifier
	* @sendmail boolean whether to send confirmation email default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function requestReset($publicid, $sendmail=NULL)
	{
		$block_status = $this->isBlocked();

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
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('login_incorrect')];
		}

		$status = $this->addRequest($id, $publicid, 'reset', $sendmail);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		$msg = ($sendmail) ?
		 $this->mod->Lang('reset_requested') :
		 $this->mod->Lang('reset_requested_loginmessage_suppressed');
		return [TRUE,$msg];
	}

	/**
	* Logs out the session, identified by session-hash
	* @hash 40-byte string
	* Returns: boolean
	*/
	public function logout($hash)
	{
		if (strlen($hash) != 40) {
			return FALSE;
		}

		return $this->deleteSession($hash);
	}

	/**
	* Change recorded context property
	* @context numeric identifier or alias for login context
	*/
	public function setContext($context)
	{
		$this->context = $context;
	}

	/**
	* Get specified property(ies) for @context
	* @context string login-context-alias or int login-context-identifier or NULL
	* @propkey string property-name or array of them (not validated here)
	* Returns: property value or assoc. array of them
	*/
	protected function getConfig($context, $propkey)
	{
		if ($context) {
			if (is_array($propkey)) {
				$sql2 = implode(',', $propkey);
			} else {
				$sql2 = $propkey;
			}
			if (is_int($context)) {
				$sql3 = 'id';
			} else {
				$sql3 = 'alias';
			}

			$sql = 'SELECT '.$sql2.' FROM '.$this->pref.'module_auth_contexts WHERE '.$sql3.'=?';
			$data = $this->db->GetRow($sql, [$context]);
			if ($data) {
				//grab defaults for 'empty' settings
				foreach ($data as $key=>&$val) {
					if (0) { //TODO empty test
						$val = $this->mod->GetPreference($key, NULL);
					}
				}
				unset($val);
				if ($sql2 == $propkey) {
					return $data[$propkey];
				} else {
					return $data;
				}
			}
		}

		//grab all defaults
		if (is_array($propkey)) {
			$data = [];
			foreach ($propkey as $key) {
				$data[$key] = $this->mod->GetPreference($key, NULL);
			}
			return $data;
		} else {
			return $this->mod->GetPreference($propkey, NULL);
		}
	}

	/**
	* Hashes the provided password using Bcrypt
	* @password plaintext string
	* Returns: hashed password string
	*/
	public function getHash($password)
	{
		$val = $this->getConfig($this->context, 'bcrypt_cost');
		return password_hash($password, PASSWORD_BCRYPT, ['cost'=>$val]);
	}

	/**
	* Gets user-enumerator for @publicid
	* @publicid string user identifier
	* Returns: user enumerator
	*/
	public function getUID($publicid)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=?';
		return $this->db->GetOne($sql, [$publicid]);
	}

	/**
	* Creates a session for user @uid
	* @uid int user enumerator
	* @remember boolean whether to setup an expiry time for the session
	* Returns: array with members 'hash','expire','expiretime','cookie_hash', or else FALSE
	*/
	protected function addSession($uid, $remember)
	{
		$userdata = $this->getBaseUser($uid);
		if (!$userdata) {
			return FALSE;
		}

		$this->deleteExistingSessions($uid);

		$val = $this->mod->GetPreference('session_salt');
		$hash = sha1(uniqid($val, TRUE));

		$data = ['hash'=>$hash,'cookie_hash'=>sha1($hash.$val)];

		$dt = new \DateTime('@'.time(), NULL);
		if ($remember) {
			$val = $this->getConfig($this->context, 'cookie_remember');
			$dt->modify('+'.$val);
			$data['expire'] = $dt->getTimestamp();
			$data['expiretime'] = $data['expire'];
		} else {
			$val = $this->getConfig($this->context, 'cookie_forget');
			$dt->modify('+'.$val);
			$data['expire'] = $dt->getTimestamp();
			$data['expiretime'] = 0;
		}

		$ip = $this->getIp();
		$agent = $_SERVER['HTTP_USER_AGENT'];

		$sql = 'INSERT INTO '.$this->pref.'module_auth_sessions (uid,hash,expire,ip,agent,cookie_hash) VALUES (?,?,?,?,?,?)';

		if (!$this->db->Execute($sql, [$uid, $hash, $data['expire'], $ip, $agent, $data['cookie_hash']])) {
			return FALSE;
		}

		return $data;
	}

	/**
	* Removes all existing sessions for user @uid
	* @uid int user enumerator
	* Returns: boolean
	*/
	protected function deleteExistingSessions($uid)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE uid=?';
		$res = $this->db->Execute($sql, [$uid]);
		return ($res != FALSE);
	}

	/**
	* Removes a session based on @hash
	* @hash string
	* Returns: boolean
	*/
	protected function deleteSession($hash)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE hash=?';
		$res = $this->db->Execute($sql, [$hash]);
		return ($res != FALSE);
	}

	/**
	* Checks if a session is valid
	* @hash string sha1-generated session identifier
	* Returns: boolean
	*/
	public function checkSession($hash)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'block') {
			return FALSE;
		}

		if (strlen($hash) != 40) { //sha1 hash length
			return FALSE;
		}

		$sql = 'SELECT id,uid,expire,ip,agent,cookie_hash FROM '.$this->pref.'module_auth_sessions WHERE hash=?';
		$row = $this->db->GetRow($sql, [$hash]);

		if (!$row) {
			return FALSE;
		}

		if ($row['expire'] < time()) {
			$this->deleteExistingSessions($row['uid']);
			return FALSE;
		}

		$ip = $this->getIp();
		if ($ip != $row['ip']) {
			return FALSE;
		}

		$val = $this->mod->GetPreference('session_salt');
		return ($row['cookie_hash'] == sha1($hash.$val));
	}

	/**
	* Retrieves the user-enumerator associated with the given session-hash
	* @hash string
	* Returns: int
	*/
	public function getSessionUID($hash)
	{
		$sql = 'SELECT uid FROM '.$this->pref.'module_auth_sessions WHERE hash=?';
		return $this->db->GetOne($sql, [$hash]);
	}

	/**
	* Method for preventing duplicates and user-recognition checks
	* Checks whether @publicid is recorded for current context
	* @publicid string user identifier
	* Returns: boolean
	*/
	public function isLoginTaken($publicid)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context=?';
		$num = $this->db->GetOne($sql, [$publicid, $this->context]);
		return ($num > 0);
	}

	/**
	* Records a new user
	* @publicid string user identifier
	* @password plaintext string
	* @email email address for messages, possibly empty
	* @sendmail  reference to boolean whether to send confirmation email messages
	* @params array of additional params default = empty
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function addUser($publicid, $password, $email, &$sendmail, $params=[])
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

		$password = $this->getHash($password);
		if (!$email) {
			$email = NULL;
		}

		$sql = 'INSERT INTO '.$this->pref.'module_auth_users (id,publicid,passhash,address,active) VALUES (?,?,?,?,?)';

		if (!$this->db->Execute($sql, [$uid, $publicid, $password, $email, $isactive])) {
			$this->deleteRequest($status[$TODO]);
			return [FALSE,$this->mod->Lang('system_error').' #03'];
		}

		if (is_array($params) && count($params) > 0) { //TODO
		}

		return [TRUE, ''];
	}

	/**
	* Gets basic user-data for the given UID
	* @uid int user enumerator
	* Returns: array with members 'uid','publicid','password','active', or else FALSE
	*/
	protected function getBaseUser($uid)
	{
		$sql = 'SELECT publicid,passhash,active FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql, [$uid]);

		if ($data) {
			$data['uid'] = $uid;
			return $data;
		}
		return FALSE;
	}

	/**
	* Gets all user-data except password,factor2 for the given UID
	* @ int $uid user enumerator
	* Returns: array with members 'uid','address','publicid','active', or else FALSE
	*/
	public function getUser($uid)
	{
		$sql = 'SELECT * FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql, [$uid]);

		if ($data) {
			unset($data['id']);
			unset($data['password']);
			$data['uid'] = $uid; //=data['id']
			return $data;
		}
		return FALSE;
	}

	/**
	* Gets publicly-accessible user-data for @publicid
	* @publicid string user identifier
	* @active optional boolean whether the user is required to be active default = TRUE
	* Returns: array with members 'publicid','address','addwhen','lastuse', or else FALSE
	*/
	public function getPublicUser($publicid, $ative=TRUE)
	{
		$sql = 'SELECT address,addwhen,lastuse FROM '.$this->pref.'module_auth_users WHERE comtext=? AND publicid=?';
		if ($active) {
			$sql .= ' AND active>0';
		}
		$data = $this->db->GetRow($sql, [$this->context,$publicid]);

		if ($data) {
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
	* @uid int user enumerator
	* @password string plaintext
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function deleteUser($uid, $password)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang(TODO)];
		}

		if (!password_verify($password, $userdata['password'])) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_users WHERE id=?';

		if (!$this->db->Execute($sql, [$uid])) {
			return [FALSE,$this->mod->Lang('system_error').' #05'];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE uid=?';

		if (!$this->db->Execute($sql, [$uid])) {
			return [FALSE,$this->mod->Lang('system_error').' #06'];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_requests WHERE uid=?';

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
		$sql = 'SELECT id,publicid FROM '.$this->pref.'module_auth_users WHERE context=? AND active>0 ORDER BY addwhen';
		return $this->db->GetAssoc($sql, [$this->context]);
	}

	/**
	* Creates an activation entry and sends publicid to user
	* @uid int user enumerator
	* @publicid string user identifier
	* @type string 'reset' or 'activate'
	* @sendmail boolean reference whether to send confirmation email
	* @fake boolean whether to treat this as a bogus notice default = FALSE
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
				$val = $this->getConfig($this->context, 'send_reset_message');
				if (!$val) {
					$sendmail = FALSE;
					return [TRUE,''];
				}
			} elseif ($type == 'activate') {
				$val = $this->getConfig($this->context, 'send_activate_message');
				if (!$val) {
					$sendmail = FALSE;
					return [TRUE,''];
				}
			}
		}

		$sql = 'SELECT id,expire FROM '.$this->pref.'module_auth_requests WHERE uid=? AND type=?';
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
		$val = $this->getConfig($this->context, 'request_key_expiration');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$val = $this->getRandomKey(self::KEYSALT);
		$key = uniqid($val, FALSE); //32-byte string

		$request_id = $this->db->GenID($this->pref.'module_auth_requests_seq');

		if (!$fake) {
			$sql = 'INSERT INTO '.$this->pref.'module_auth_requests (id,uid,expire,rkey,type) VALUES (?,?,?,?,?)';

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

		$site_name = $this->getConfig($this->context, 'context_sender'); //TODO this gets a personal name

		$mlr->reset();
		if (1) { //TODO default sender isn't wanted
			$site_from = $this->getConfig($this->context, 'context_address');
			$mlr->SetFrom($site_from, $site_name);
		}
		$mlr->AddAddress($email, '');

		$mlr->IsHTML(TRUE);

		//construct frontend-url (so no admin publicid is needed)
		$u = $this->mod->create_url('cntnt01', 'validate', '', [
				'cauthc'=>$key,
				'rauthr'=>$request_id]);
		$url = str_replace('&amp;', '&', $u);

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
	* @key 32-byte string from uniqid() with 19-random-bytes prefix
	* @type string 'reset' or 'activate'
	* Returns: array 0=>T/F for success, 1=>message, if success then also 'id','uid'
	*/
	public function getRequest($key, $type)
	{
		$sql = 'SELECT id,uid,expire FROM '.$this->pref.'module_auth_requests WHERE rkey=? AND type=?';
		$row = $this->db->GetRow($sql, [$key, $type]);

		if (!$row) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang($type.'key_incorrect')];
		}

		if ($row['expire'] < time()) {
			$this->addAttempt();
			$this->deleteRequest($row['id']);
			return [FALSE,$this->mod->Lang($type.'key_expired')];
		}

		return [0=>TRUE,1=>'','id'=>$row['id'],'uid'=>$row['uid']];
	}

	/**
	* Deletes request from database
	* @id int request enumerator
	* Returns: boolean
	*/
	protected function deleteRequest($id)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_requests WHERE id=?';
		$res = $this->db->Execute($sql, [$id]);
		return ($res != FALSE);
	}

	/**
	* Verifies that @publicid is a valid publicid indentifier
	* @publicid string user identifier
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function validateLogin($publicid)
	{
		$val = (int)$this->getConfig($this->context, 'login_min_length');
		if ($val > 0 && strlen($publicid) < $val) {
			return [FALSE,$this->mod->Lang('login_short')];
		}

		$val = (int)$this->getConfig($this->context, 'login_max_length');
		if ($val > 0 && strlen($publicid) > $val) {
			return [FALSE,$this->mod->Lang('login_long')];
		}

		if (preg_match(self::EMAILPATN, $publicid)) {
			$val = $this->getConfig($this->context, 'email_banlist');
			if ($val) {
				$parts = explode('@', $publicid);
				$bannedDomains = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
				if (in_array(strtolower($parts[1]), $bannedDomain)) {
					return [FALSE,$this->mod->Lang('email_banned')];
				}
			}
		}

		return [TRUE,''];
	}

	/**
	* Verifies that @email is an acceptable email address
	* @email string
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
	* @uid int user enumerator
	* @password plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function matchPassword($uid, $password)
	{
		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			return [FALSE,$this->mod->Lang('system_error').' #11'];
		}

		if (!password_verify($password, $userdata['password'])) {
			return [FALSE,$this->mod->Lang('password_notvalid')];
		}
		return [TRUE,''];
	}

	/**
	* Verifies that @password respects security requirements
	* @password plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function validatePassword($password)
	{
		$val = (int)$this->getConfig($this->context, 'password_min_length');
		if ($val > 0 && strlen($password) < $val) {
			return [FALSE,$this->mod->Lang('password_short')];
		}

		require __DIR__.DIRECTORY_SEPARATOR.zxcvbn.DIRECTORY_SEPARATOR.Zxcvbn.php;
		$zxcvbn = new ZxcvbnPhp\Zxcvbn();
		$check = $zxcvbn->passwordStrength($password);

		$val = (int)$this->getConfig($this->context, 'password_min_score');
		if ($check['score'] + 1 < $val) { //returned value 0..4, public uses 1..5
			return [FALSE,$this->mod->Lang('password_weak')];
		}

		return [TRUE,''];
	}

	/**
	* Allows a user to reset her/his password after requesting a reset
	* @key string
	* @password plaintext string
	* @repeatpassword plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function resetPassword($key, $password, $repeatpassword)
	{
		$block_status = $this->isBlocked();

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
			$this->addAttempt();
			$this->deleteRequest($data['id']);
			return [FALSE,$this->mod->Lang('system_error').' #11'];
		}

		if (password_verify($password, $userdata['password'])) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('newpassword_match')];
		}

		$password = $this->getHash($password);
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
		$res = $this->db->Execute($sql, [$password, $data['uid']]);

		if ($res) {
			$this->deleteRequest($data['id']);
			return [TRUE,$this->mod->Lang('password_reset')];
		}
		return [FALSE,$this->mod->Lang('system_error').' #12'];
	}

	/**
	* Changes a user's password
	* @uid int user enumerator
	* @currpass plaintext string
	* @newpass plaintext string
	* @repeatnewpass plaintext string
	* Returns: array 0->T/F, 1=>message
	*/
	public function changePassword($uid, $currpass, $newpass, $repeatnewpass)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$status = $this->matchPassword($uid, $currpass);

		if (!$status[0]) {
			$this->addAttempt();
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
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('system_error').' #13'];
		}

		if (!password_verify($currpass, $userdata['password'])) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		$newpass = $this->getHash($newpass);

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
		$this->db->Execute($sql, [$newpass, $uid]);
		return [TRUE,$this->mod->Lang('password_changed')];
	}

	/**
	* Compare user's password with given password
	* @uid int user enumerator
	* @password_for_check string
	* Returns: boolean indicating match
	*/
	public function comparePasswords($uid, $password_for_check)
	{
		$sql = 'SELECT passhash FROM '.$this->pref.'module_auth_users WHERE id=?';
		$password = $this->db->GetOne($sql, [$uid]);

		if ($password) {
			return password_verify($password_for_check, $password);
		}
		return FALSE;
	}

	/**
	* Changes a user's publicid name
	* @uid int user enumerator
	* @publicid string user identifier
	* @password plaintext string
	* Returns: array 0=>T/F, 1=>message
	*/
	public function changelogin($uid, $publicid, $password)
	{
		$block_status = $this->isBlocked();

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
			$this->addAttempt();
			return $status;
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('system_error').' #14'];
		}

		if (!password_verify($password, $userdata['password'])) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		if ($publicid == $userdata['publicid']) {
			$this->addAttempt();
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
	* @publicid string user identifier
	* @sendmail default = NULL  whether to send email notice
	* Returns: array 0=>T/F, 1=>message
	*/
	public function resendActivation($publicid, $sendmail=NULL)
	{
		$block_status = $this->isBlocked();

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

		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=?';
		$id = $this->db->GetOne($sql, [$publicid]);

		if ($id == FALSE) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('login_incorrect')];
		}

		$userdata = $this->getBaseUser($id);

		if ($userdata['active']) {
			$this->addAttempt();
			return [FALSE,$this->mod->Lang('already_activated')];
		}

		$status = $this->addRequest($id, $publicid, 'activate', $sendmail);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		return [TRUE,$this->mod->Lang('activation_sent')];
	}

	/**
	* Reports access-status for the current ip address
	* Returns: string 'allow','verify' or 'block'
	*/
	public function isBlocked()
	{
		$ip = $this->getIp();
		$this->deleteAttempts($ip, FALSE);
		$sql = 'SELECT count(1) AS tries FROM '.$this->pref.'module_auth_attempts WHERE ip=?';
		$tries = $this->db->GetOne($sql, [$ip]);

		$val = (int)$this->getConfig($this->context, 'attempts_before_verify');
		if ($val > 0 && $tries < $val) {
			return 'allow';
		}

		$val = (int)$this->getConfig($this->context, 'attempts_before_ban');
		if ($val > 0 && $tries < $val) {
			return 'verify';
		}

		return 'block';
	}

	/**
	* Adds an attempt to database
	* Returns: boolean indicating success
	*/
	protected function addAttempt()
	{
		$ip = $this->getIp();
		$dt = new \DateTime('@'.time(), NULL);
		$val = $this->getConfig($this->context, 'attack_mitigation_span');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$sql = 'INSERT INTO '.$this->pref.'module_auth_attempts (ip,expire) VALUES (?,?)';
		$res = $this->db->Execute($sql, [$ip, $expiretime]);
		return ($res != FALSE);
	}

	/**
	* Deletes some/all attempts for a given IP from database
	* @ip string
	* @all boolean default = FALSE
	* Returns: boolean indicating success
	*/
	protected function deleteAttempts($ip, $all=FALSE)
	{
		if ($all) {
			$sql = 'DELETE FROM '.$this->pref.'module_auth_attempts WHERE ip=?';
			$res = $this->db->Execute($sql, [$ip]);
		} else {
			$sql = 'DELETE FROM '.$this->pref.'module_auth_attempts WHERE ip=? AND expire<?';
			$nowtime = time();
			$res = $this->db->Execute($sql, [$ip, $nowtime]);
		}
		return ($res != FALSE);
	}

	/**
	* Returns a random string of a specified length
	* @length int wanted byte-count
	* Returns: string
	*/
	public function getRandomKey($length=20)
	{
		$chars = '01234567890123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		$key = str_repeat('0', $length);
		for ($i = 0; $i < $length; $i++) {
			$key[$i] = $chars[mt_rand(0, 81)];
		}
		return $key;
	}

	/**
	* Get IP address
	* Returns: string $ip
	*/
	protected function getIp()
	{
		if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			return $_SERVER['HTTP_X_FORWARDED_FOR'];
		} else {
			return $_SERVER['REMOTE_ADDR'];
		}
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
		$val = $this->getConfig($this->context, 'cookie_name');
		return (isset($_COOKIE[$val]) && $this->checkSession($_COOKIE[$val]));
	}

	/**
	* Gets current session hash
	* Returns: string
	*/
	public function getSessionHash()
	{
		$val = $this->getConfig($this->context, 'cookie_name');
		return $_COOKIE[$val];
	}

	/**
	Gets a captcha-suitable string and URL of a correspoding png-image file
	Requires PHP extension GD 1 or 2
	Returns: 2-member array
	 'code' = @length-byte string
   'image_src' = URL of cached png image displaying 'code' string
	*/
	public function getCaptcha($length = 8)
	{
		$config = \cmsms()->GetConfig();
		$tmpdir = $config['root_path'].DIRECTORY_SEPARATOR.'tmp'.DIRECTORY_SEPARATOR.'cache';

		$funcs = new Auther\Captcha\SimpleCaptcha();
		$data = $funcs->generate([
			'background' => 'plain.png',
			'font' => 'Roboto-Regular.ttf',
			'size' => 20,
			'color' => '#000',
			'length' => $length,
			'path' => $tmpdir,
		]);

		$rooturl = (empty($_SERVER['HTTPS'])) ? $config['root_url'] : $config['ssl_url'];
		$url = str_replace(array($config['root_path'],DIRECTORY_SEPARATOR), array($rooturl,'/'), $tmpdir);
		$url .= '/'.$data['file'];
		return ['code' => $data['code'], 'image_src' => $url];
	}
}
