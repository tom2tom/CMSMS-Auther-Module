<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Derived originally from PHPAuth <https://www.phpclasses.org/package/9887-PHP-Register-and-publicid-users-stored-in-a-database.html>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
# Requires PHP 5.4+
#----------------------------------------------------------------------
namespace Auther;

/* TODO
2FA support
 captcha?
send events API (parameters) $this->mod->SendEvent('OnX',$parms);
*/

include __DIR__.DIRECTORY_SEPARATOR.'password.php';

class Auth extends Session
{
	const PATNEMAIL = '/^.+@.+\..+$/';
	const NAMEDIR = 'usernames'; //subdir name
	const PHRASEDIR = 'phrases';

	public $loginisemail;
	public $addressisemail;
	protected $trainers = ['big.txt', 'good.txt', 'bad.txt', 'matrix.txt'];
	protected $namepath;
	protected $phrasepath;
	protected $nametrained = FALSE;
	protected $phrasetrained = FALSE;

	public function __construct(&$mod, $context=0)
	{
		parent::__construct($mod, $context);
	}

	//~~~~~~~~~~~~~ PARAMETER VALIDATION ~~~~~~~~~~~~~~~~~

	/**
	* Verifies that @login is an acceptable login identifier
	* @login: string user identifier
	* @explicit: optional boolean whether to report login-is-taken or just invalid default = FALSE
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function validateLogin($login, $explicit=FALSE)
	{
		$val = (int)$this->GetConfig('login_min_length');
		if ($val > 0 && strlen($login) < $val) {
			return [FALSE, $this->mod->Lang('login_short')];
		}

		$val = (int)$this->GetConfig('login_max_length');
		if ($val > 0 && strlen($login) > $val) {
			return [FALSE, $this->mod->Lang('login_long')];
		}

		$val = $this->GetConfig('email_login');
		if ($val) {
			if (!preg_match(self::PATNEMAIL, $login)) {
				return [FALSE, $this->mod->Lang('invalid','TODO')];
			}
		} else {
			$val = preg_match(self::PATNEMAIL, $login);
		}
		if ($val) {
			$this->loginisemail = TRUE;
			$val = $this->GetConfig('email_banlist');
			if ($val) {
				$parts = explode('@', $login);
				$bannedDomains = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
				if (in_array(strtolower($parts[1]), $bannedDomains)) {
					return [FALSE,$this->mod->Lang('email_banned')];
				}
			}
		} else {
			$this->loginisemail = FALSE;
		}

		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id=?';
		if ($this->db->GetOne($sql, [$login, $this->context])) {
			$key = ($explicit) ? 'login_taken' : 'login_notvalid';
			return [FALSE, $this->mod->Lang($key)];
		}

		return [TRUE,''];
	}

	/**
	* Verifies (somewhat slowly) that @login is not 'gibberish'
	* @login: string user identifier
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function sensibleLogin($login)
	{
		if (!$this->nametrained) {
			$fp = [];
			$this->namepath = __DIR__.DIRECTORY_SEPARATOR.self::NAMEDIR.DIRECTORY_SEPARATOR;
			foreach ($this->trainers as $fn) {
				$fp[] = $this->namepath.$fn;
			}
			$this->nametrained = Gibberish::train($fp[0], $fp[1], $fp[2], $fp[3]);
		}
		if ($this->nametrained) {
			if (extension_loaded('mbstring')) {
				$t = mb_convert_case($login, MB_CASE_LOWER, 'UTF-8'); //TODO first encoding?
			} else {
				$t = strtolower($login);
			}
			$fp = $this->namepath.$this->trainers[3];
			$val = Gibberish::test($t, $fp, FALSE); //TODO get & evaluate raw score
			if (!$val) {
				return [FALSE, $this->mod->Lang('login_notvalid')];
			}
		}
		return [TRUE,''];
	}

	/**
	* Verifies that @password respects security requirements
	* @password: plaintext string
	* Returns: array [0]=boolean for success, [1]=message or ''
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
	* Verifies that @name is an acceptable user-name
	* @name: string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function validateName($name)
	{
		$val = $this->GetConfig('name_required');
		if ($val && !$name) {
			return [FALSE, $this->mod->Lang('missing_name')]; //TODO has appended 'yet'
		}
		if (strlen($name) < 2 || preg_match('/[\d=|"-\,\?]/', $name)) {
			return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('name'))];
		}
		return [TRUE, ''];
	}

	/**
	* Verifies (somewhat slowly) that @name is not 'gibberish'
	* @name: string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function sensibleName($name)
	{
		if (!$this->phrasetrained) {
			$fp = [];
			$this->phrasepath = __DIR__.DIRECTORY_SEPARATOR.self::PHRASEDIR.DIRECTORY_SEPARATOR;
			foreach ($this->trainers as $fn) {
				$fp[] = $this->phrasepath.$fn;
			}
			$this->phrasetrained = Gibberish::train($fp[0], $fp[1], $fp[2], $fp[3]);
		}
		if ($this->phrasetrained) {
			$fp = $this->phrasepath.$this->trainers[3];
			$val = Gibberish::test($name, $fp, FALSE);
			if (!$val) { //TODO
				return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('name'))];
			}
		}
		return [TRUE, ''];
	}

	/**
	* Verifies that @address is an acceptable contact address
	* Must be called after login is validated
	* @address: string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function validateAddress($address)
	{
		$val = $this->GetConfig('address_required');
		if ($val && !$address) {
			return [FALSE, $this->mod->Lang('missing_address')];
		}
		$val = $this->GetConfig('email_required');
		if ($val) {
			$res = $this->validateEmail($address);
			$this->addressisemail = $res[0];
			if (!$res[0] && empty($this->loginisemail)) {
				return [FALSE, $res[1]];
			}
		}
		return [TRUE,''];
	}

	/**
	* Verifies that @email is an acceptable email address
	* @email: string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function validateEmail($email)
	{
		if (!$email || !preg_match(self::PATNEMAIL, $email)) {
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

	//~~~~~~~~~~~~~ REGISTRATION ~~~~~~~~~~~~~~~~~

	/**
	* Creates and records a user
	* @login: string user identifier
	* @password: plaintext string
	* @repeatpass: plaintext string
	* @email: email address for notices to the user default = ''
	* @params: array extra user-parameters for self::addUser() default = empty
	* @sendmail: bool whether to send email-messages if possible default = NULL
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function register($login, $password, $repeatpass, $email='', $params=[], $sendmail=NULL)
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
		$status = $this->validateLogin($login);
		if (!$status[0]) {
			return $status;
		}

		if ($this->isLoginTaken($login)) {
			return [FALSE,$this->mod->Lang('login_taken')];
		}

		// Validate password
		$status = $this->validatePassword($password);
		if (!$status[0]) {
			return $status;
		}

		if ($password !== $repeatpass) {
			return [FALSE,$this->mod->Lang('password_nomatch')];
		}

		if ($email) {
			// Validate email
			$status = $this->validateEmail($email);
			if (!$status[0]) {
				return $status;
			}
		}

		$status = $this->addUser($login, $password, $email, $sendmail, $params);
		if (!$status[0]) {
			return $status;
		}

		$parms = []; //TODO API
		$this->mod->SendEvent('OnRegister', $parms);

		$msg = ($sendmail) ?
		 $this->mod->Lang('register_success') :
		 $this->mod->Lang('register_success_message_suppressed');
		return [TRUE,$msg];
	}

	/**
	* Checks whether @login is recorded for current context and active, and
	*  @password (if not FALSE) is valid. A session is created/updated as appropriate
	* @login: string user identifier
	* @password: plaintext string, or FALSE to skip password-validation
	* @active: optional boolean whether to check for active user, default TRUE
	* @fast: optional boolean whether to return immediately if not recognized, default FALSE
	* Returns: 2-member array [0]=boolean indicating success [1]=array of data from row of session table
	*/
	public function isRegistered($login, $password, $active=TRUE, $fast=FALSE)
	{
		$sql = 'SELECT id,privhash,active FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id=?';
		$userdata = $this->db->GetRow($sql, [$login, $this->context]);
		$uid = ($userdata) ? $userdata['id'] : -1;
		$ip = $this->GetIp();
		$sdata = $this->SessionExists($uid, $ip);
		if ($userdata && (!$active || $userdata['active'] > 0)) {
			if ($password === FALSE) {
				if ($sdata) {
					//cleanup TODO change status if NEW_FOR_IP
					$sql = 'UPDATE '.$this->pref.'module_auth_cache SET user_id=?,attempts=1 WHERE token=?';
					$this->db->Execute($sql, [$uid, $token]);
					$sdata['user_id'] = $uid;
					$sdata['attempts'] = 1;
				} else {
					$token = $this->MakeUserSession($uid);
					$sql = 'SELECT * FROM '.$this->pref.'module_auth_cache WHERE token=?';
					$sdata = $this->db->GetRow($sql, [$token]);
				}
				return [TRUE, $sdata];
			}
			if ($sdata) {
				$this->Addttempt();
				$sdata['attempts']++;
			} else {
				$token = $this->MakeUserSession($uid);
				$sql = 'SELECT * FROM '.$this->pref.'module_auth_cache WHERE token=?';
				$sdata = $this->db->GetRow($sql, [$token]);
			}
			$tries = ($fast) ? 0:$sdata['attempts'];
			$res = $this->doPasswordCheck($password, $userdata['privhash'], $tries);
			return [$res, $sdata];
		} else {
			if ($sdata) {
				$this->Addttempt();
				$sdata['attempts']++;
			} else {
				$token = $this->MakeSourceSession($ip);
				$sql = 'SELECT * FROM '.$this->pref.'module_auth_cache WHERE token=?';
				$sdata = $this->db->GetRow($sql, [$token]);
			}
		}
		if (!$fast) {
			$t = min(2000, $sdata['attempts'] * 500);
			usleep($t * 1000);
		}
		return [FALSE, $sdata];
	}

	//~~~~~~~~~~~~~ SESSION ~~~~~~~~~~~~~~~~~

	/**
	* Logs a user in
	* @login: string user identifier
	* @password: plaintext string
	* @nonce: default = FALSE
	* @remember: boolean whether to setup session-expiry-time in self::AddSession() default = FALSE
	* Returns: array, [0]=boolean for success, [1]=message or '', if [0] then also session-parameters: 'token','expire'
	*/
	public function login($login, $password, $nonce=FALSE, $remember=FALSE)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				$parms = []; //TODO API
				$this->mod->SendEvent('OnLoginFail', $parms);
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$uid = $this->getUserID($login);

		if (!$uid) {
			$this->AddAttempt();
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('login_incorrect')];
		}

		$userdata = $this->getUserBase($uid);

		if (!$userdata['active']) {
			$this->AddAttempt();
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('account_inactive')];
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->AddAttempt();
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		if (!is_bool($remember)) {
			$this->AddAttempt();
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('remember_me_invalid')];
		}

		$sessiondata = $this->AddSession($uid, $remember);

		if (!$sessiondata) {
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE,$this->mod->Lang('system_error', '#01')];
		}

		$parms = []; //TODO API
		$this->mod->SendEvent('OnLogin', $parms);

		$data = [TRUE,$this->mod->Lang('logged_in')];
		$data['token'] = $sessiondata['token'];
		$data['expire'] = $sessiondata['expiretime'];
		return $data;
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

	//~~~~~~~~~~~~~ REQUEST OPERATIONS ~~~~~~~~~~~~~~~~~

	/**
	* If parameters so specify, creates a request and sends confirmation-email to the user
	* This is a low-level method, without blockage check
	* @login: string user identifier
	* @type: string 'reset' or 'activate'
	* @sendmail: reference to flag whether to send confirmation email, boolean, or NULL to check context property
	* @password: optional plaintext password to be advised instead of URL, default = FALSE
	* Returns: array [0]=boolean for success, [1]=message or '' or request-token
	*  @sendmail may be altered e.g. FALSE if not sent
	*/
	protected function addRequest($login, $type, &$sendmail, $password=FALSE)
	{
		if (!($type == 'activate' || $type == 'reset')) {
			$sendmail = FALSE;
			return [FALSE, $this->mod->Lang('system_error', '#02')];
		}

		if ($sendmail === NULL) {
			// not set explicitly, check config data
			$sendmail = TRUE;
			if ($type == 'activate') {
				$val = $this->GetConfig('send_activate_message');
				if (!$val) {
					$sendmail = FALSE;
					return [TRUE, ''];
				}
			} elseif ($type == 'reset') {
				$val = $this->GetConfig('send_reset_message');
				if (!$val) {
					$sendmail = FALSE;
					return [TRUE, ''];
				}
			}
		}

		$sql = 'SELECT id,address,active FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id=?';
		$row = $this->db->GetRow($sql, [$login, $this->context]);
		if ($row) {
			$uid = (int)$row['id'];
			$t = $row['address'];
			if ($t && preg_match(self::PATNEMAIL, $t)) {
				$email = $t;
			} else {
				$t = $login;
				if ($t && preg_match(self::PATNEMAIL, $t)) {
					$email = $t;
				} else {
					$sendmail = FALSE;
					return [FALSE, $this->mod->Lang('temp_notsent')];
				}
			}
		} else {
			$sendmail = FALSE;
			return [FALSE, $this->mod->Lang('system_error', '#03')];
		}

		if ($type == 'activate') {
			if ($row['active']) {
				$sendmail = FALSE;
				return [FALSE, $this->mod->Lang('already_activated')];
			}
		}

		$itype = ($type == 'activate') ? parent::REQUEST_ACTIV : parent::REQUEST_RESET; //'interim' identifier, pending token
		$sql = 'SELECT token,expire FROM '.$this->pref.'module_auth_cache WHERE user_id=? AND lastmode=?';
		$row = $this->db->GetRow($sql, [$uid, $itype]);

		if ($row) {
			if ($row['expire'] > time()) {
				$sendmail = FALSE;
				return [FALSE, $this->mod->Lang('request_exists')];
			}
			$this->deleteRequest($row['token']);
		}

		$token = $this->UniqueToken(24);

		$dt = new \DateTime('@'.time(), NULL);
		$val = $this->GetConfig('request_key_expiration');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$sql = 'INSERT INTO '.$this->pref.'module_auth_cache (token,user_id,expire,lastmode) VALUES (?,?,?,?)';

		if (!$this->db->Execute($sql, [$token, $uid, $expiretime, $itype])) {
			$sendmail = FALSE;
			return [FALSE, $this->mod->Lang('system_error', '#04')];
		}

		if (!$sendmail) {
			return [TRUE, ''];
		}

		if ($this->mod->before20) {
			$mlr = \cms_utils::get_module('CMSMailer');
			if ($mlr) {
				$mlr->_load();
			} else {
				$sendmail = FALSE;
				$this->deleteRequest($token);
				return [FALSE, $this->mod->Lang('system_error', 'CMSMailer N/A')];
			}
		} else {
			$mlr = new \cms_mailer();
		}

		$mlr->reset();
		$sender = $this->GetConfig('context_sender');
		if ($sender) {
			$from = $this->GetConfig('context_address');
			$mlr->SetFrom($from, $sender);
		}
		$mlr->AddAddress($email, '');

		$mlr->IsHTML(TRUE);

		$site = $this->GetConfig('context_site');
		if ($type == 'activate') {
			$mlr->SetSubject($this->mod->Lang('email_activation_subject', $site));
		} else {
			$mlr->SetSubject($this->mod->Lang('email_reset_subject', $site));
		}

		if ($password) {
			if ($type == 'activate') {
				$mlr->SetBody($this->mod->Lang('email_activation2_body', $password, $site));
				$mlr->SetAltBody($this->mod->Lang('email_activation2_altbody', $password, $site));
			} else { //reset
				$mlr->SetBody($this->mod->Lang('email_reset2_body', $password, $site));
				$mlr->SetAltBody($this->mod->Lang('email_reset2_altbody', $password, $site));
			}
		} else {
			//construct frontend-url (so no admin login is needed)
			$u = $this->mod->create_url('cntnt01', 'validate', '', ['cauthc'=>$token]);
			$url = strtr($u, '&amp;', '&');

			if ($type == 'activate') {
				$mlr->SetBody($this->mod->Lang('email_activation_body', $url, $site));
				$mlr->SetAltBody($this->mod->Lang('email_activation_altbody', $url, $site));
			} else { //reset
				$mlr->SetBody($this->mod->Lang('email_reset_body', $url, $site));
				$mlr->SetAltBody($this->mod->Lang('email_reset_altbody', $url, $site));
			}
		}

		if ($mlr->Send()) {
			$mlr->reset();
			return [TRUE, $token];
		} else {
			$this->deleteRequest($token);
			$msg = $mlr->GetErrorInfo();
			$mlr->reset();
			return [FALSE, $msg];
		}
	}

	/**
	* Returns request data if @token is valid
	* @token: 24-byte string from UniqueToken()
	* @type: string 'reset' or 'activate', only for error-message namespacing
	* Returns: array [0]=boolean for success, [1]=message or '', if [0] then also 'uid'
	*/
	public function getRequest($token, $type)
	{
		$sql = 'SELECT user_id,expire FROM '.$this->pref.'module_auth_cache WHERE token=?';
		$row = $this->db->GetRow($sql, [$token]);

		if (!$row) {
			$this->AddAttempt();
			return [FALSE, $this->mod->Lang($type.'key_incorrect')];
		}

		if ($row['expire'] < time()) {
			$this->AddAttempt();
			$this->deleteRequest($token);
			return [FALSE, $this->mod->Lang($type.'key_expired')];
		}

		return [0=>TRUE, 1=>'', 'uid'=>$row['uid']];
	}

	/**
	* @token: string request identifier
	* Returns: boolean
	* Deletes a request
	*/
	protected function deleteRequest($token)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_cache WHERE token=?';
		$res = $this->db->Execute($sql, [$token]);
		return ($res != FALSE);
	}

	/**
	* Stores a password-reset request, and sends confirmation email to the user if parameters warrant that
	* @login: string user identifier
	* @sendmail: boolean whether to send confirmation email, default=NULL hence per context property
	* @password: optional plaintext password to be sent to user instead of an URL, default = FALSE
	* Returns: array [0]=boolean for success, [1]=message
	*/
	public function requestReset($login, $sendmail=NULL, $password=FALSE)
	{
		if ($this->IsBlocked() == 'block') {
			return [FALSE, $this->mod->Lang('user_blocked')];
		}

		$status = $this->addRequest($login, 'reset', $sendmail, $password);
		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		$msg = ($sendmail) ? 'reset_sent' : 'reset_created';
		return [TRUE, $this->mod->Lang($msg)];
	}

	/**
	* Stores an account-activation request, and sends confirmation email to the user if parameters warrant that
	* @login: string user identifier
	* @sendmail: boolean whether to send confirmation email, default=NULL hence per context property
	* @password: optional plaintext password to be sent to user instead of an URL, default = FALSE
	* Returns: array [0]=boolean for success, [1]=message
	*/
	public function requestActivation($login, $sendmail=NULL, $password=FALSE)
	{
		if ($this->IsBlocked() == 'block') {
			return [FALSE, $this->mod->Lang('user_blocked')];
		}


		$status = $this->addRequest($login, 'activate', $sendmail, $password);
		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		$msg = ($sendmail) ? 'activation_sent' : 'activation_created';
		return [TRUE, $this->mod->Lang($msg)];
	}

	//~~~~~~~~~~~~~ USER OPERATIONS ~~~~~~~~~~~~~~~~~

	/**
	* Activates a user's account
	* @token: string 24-byte token
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function activate($token)
	{
		if ($this->IsBlocked() == 'block') {
			return [FALSE, $this->mod->Lang('user_blocked')];
		}

		if (strlen($token) !== 24) {
			$this->AddAttempt();
			return [FALSE, $this->mod->Lang('activationkey_invalid')];
		}

		$data = $this->getRequest($token, 'activate');

		if (!$data[0]) {
			$this->AddAttempt();
			return $data;
		}

		$userdata = $this->getUserBase($data['uid']);
		if ($userdata['active']) {
			$this->AddAttempt();
			$this->deleteRequest($token);
			return [FALSE, $this->mod->Lang('system_error', '#07')];
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET active=1 WHERE id=?';
		$this->db->Execute($sql, [$data['uid']]);

		$this->deleteRequest($token);

		return [TRUE, $this->mod->Lang('account_activated')];
	}

	/**
	* Changes a user's login name
	* @uid: int user enumerator
	* @login: string user identifier
	* @password: plaintext string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function changeLogin($uid, $login, $password)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		$status = $this->validateLogin($login);

		if (!$status[0]) {
			return $status;
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->AddAttempt();
			return $status;
		}

		$userdata = $this->getUserBase($uid);

		if (!$userdata) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('system_error', '#05')];
		}

		if (!$this->doPasswordCheck($password, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		if ($login == $userdata['publicid']) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('newlogin_match')];
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET publicid=? WHERE id=?';
		$res = $this->db->Execute($sql, [$login, $uid]);

		if ($res == FALSE) {
			return [FALSE,$this->mod->Lang('system_error', '#06')];
		}

		return [TRUE,$this->mod->Lang('login_changed')];
	}

	/**
	* Method for preventing duplicates and user-recognition checks
	* Checks whether @login is recorded for current context
	* @login: string user identifier
	* Returns: boolean
	*/
	public function isLoginTaken($login)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id=?';
		$num = $this->db->GetOne($sql, [$login, $this->context]);
		return ($num > 0);
	}

	/**
	* Gets all user-data except password for @uid
	* @uid: int user enumerator
	* @raw: whether to decrypt relevant values, default = FALSE
	* Returns: array with members uid,publicid,name,address,context_id,addwhen,lastuse,nameswap,active or else FALSE
	*/
	public function getUser($uid, $raw=FALSE)
	{
		$sql = 'SELECT * FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql, [$uid]);

		if ($data) {
			unset($data['id']);
			unset($data['privhash']);
			if (!$raw) {
				$funcs = new Crypter();
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
	* Gets password for @uid
	* @uid: int user enumerator
	* @raw: whether to encode the value, default = FALSE
	* Returns: string, raw or H-packed password, or else FALSE
	*/
	public function getUserPassword($uid, $raw=FALSE)
	{
		$sql = 'SELECT privhash FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetOne($sql, [$uid]);

		if ($data) {
			if ($raw) {
				return $data;
			}
			return pack('H*', $data);
		}
		return FALSE;
	}

	/**
	* Get user-enumerator for @login (whether or not currently active)
	* @login: string user/account identifier
	* Returns: enumerator or FALSE
	*/
	public function getUserID($login)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id=?';
		return $this->db->GetOne($sql, [$login, $this->context]);
	}

	/**
	* Gets some user-data for @uid
	* @uid: int user enumerator
	* Returns: array with members uid,publicid,privhash,active or else FALSE
	*/
	protected function getUserBase($uid)
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
	* Gets publicly-accessible user-data for @login
	* @login: string user identifier
	* @active: optional boolean whether the user is required to be active default = TRUE
	* Returns: array with members publicid,name,address,addwhen,lastuse[,active] or else FALSE
	*/
	public function getUserPublic($login, $active=TRUE)
	{
		$sql = 'SELECT name,address,addwhen,lastuse';
		if (!$active) {
			$sql .= ',active';
		}
		$sql .= ' FROM '.$this->pref.'module_auth_users WHERE publicid=? AND context_id=?';
		if ($active) {
			$sql .= ' AND active>0';
		}
		$data = $this->db->GetRow($sql, [$login, $this->context]);

		if ($data) {
			$funcs = new Crypter();
			$data['name'] = $funcs->decrypt_value($this->mod, $data['name']);
			$data['address'] = $funcs->decrypt_value($this->mod, $data['address']);
//TODO zone offset
			$dt = new \DateTime('@0',NULL);
			$dt->setTimestamp($data['addwhen']);
			$data['addwhen'] = $dt->format('Y-m-d H:i:s');
			$dt->setTimestamp($data['lastuse']);
			$data['lastuse'] = $dt->format('Y-m-d H:i:s');
			$data['publicid'] = $login;
			return $data;
		}
		return FALSE;
	}

	/**
	* Gets specified user-data for @login
	* @login: string user identifier, or array of them
	* @props: optional string table field-name, or '*' or array of field names, default = '*'
	* @active: optional boolean whether the user(s) is/are required to be active, default = TRUE
	* Returns: associative array or else FALSE
	*/
	public function getUserProperties($login, $props='*', $active=TRUE)
	{
		if (is_array($props)) {
			$namers = implode(',',$props);
		} elseif ($props == '*') {
			$namers = 'id,publicid,name,address,addwhen,lastuse,nameswap,active'; //exclude a few of the fields
		} else {
			$namers = $props;
		}
		$sql = 'SELECT '.$namers.' FROM '.$this->pref.'module_auth_users WHERE context_id=?';
		$args = [$this->context];

		if (is_array($login)) {
			$fillers = str_repeat('?,', count($login) - 1);
			$sql .= ' AND publicid IN ('.$fillers.'?)';
			$args = array_merge($args,$login);
		} else {
			$sql .= ' AND publicid=?';
			$args[] = $login;
		}

		if ($active) {
			$sql .= ' AND active>0';
		}
		$data = $this->db->GetArray($sql, $args);

		if ($data) {
			$funcs = new Crypter();
//TODO zone offset
			$dt = new \DateTime('@0',NULL);
			foreach ($data as &$one) {
				if (!empty($one['name'])) {
					$one['name'] = $funcs->decrypt_value($this->mod, $one['name']);
				}
				if (!empty($one['address'])) {
					$one['address'] = $funcs->decrypt_value($this->mod, $one['address']);
				}
				if (!empty($one['addwhen'])) {
					$dt->setTimestamp($one['addwhen']);
					$one['addwhen'] = $dt->format('Y-m-d H:i:s');
				}
				if (!empty($one['lastuse'])) {
					$dt->setTimestamp($one['lastuse']);
					$one['lastuse'] = $dt->format('Y-m-d H:i:s');
				}
			}
			unset($one);
			return $data;
		}
		return FALSE;
	}

	/**
	* Gets some data for all active users of the current context
	* Returns: associative array, each member of which is uid=>login, or else FALSE
	*/
	public function getActiveUsers()
	{
		$sql = 'SELECT id,publicid FROM '.$this->pref.'module_auth_users WHERE context_id=? AND active>0 ORDER BY addwhen';
		return $this->db->GetAssoc($sql, [$this->context]);
	}

	/**
	* Gets some specific data for all, or all active, users of the current context
	* @active: optional boolean, whether to report for active-users only, default = TRUE
	* @raw: optional boolean, whether to return encrypted data as-is, default = FALSE
	* Returns: array, each member of which has user_id,publicid,name,address,nameswap or else FALSE
	*/
	public function getPublicUsers($active=TRUE, $raw=FALSE)
	{
		$sql = 'SELECT id,publicid,name,address,nameswap FROM '.$this->pref.'module_auth_users WHERE context_id=?';
		if ($active) {
			$sql .= ' AND active>0';
		}
		$sql .= ' ORDER BY publicid';
		$data = $this->db->GetArray($sql, [$this->context]);
		if ($data && !$raw) {
			$funcs = new Crypter();
			$pw = $funcs->decrypt_preference($this->mod, 'masterpass');
			foreach ($data as &$one) {
				$one['name'] = $funcs->decrypt_value($this->mod, $one['name'], $pw);
				$one['address'] = $funcs->decrypt_value($this->mod, $one['address'], $pw);
			}
			unset ($one);
		}
		return $data;
	}

	/**
	* Records a new user
	* @login: string user identifier
	* @password: plaintext string
	* @name: string user name
	* @address: email or other type of address for messages, possibly empty
	* @sendmail:  reference to flag (T/F or NULL) whether to send confirmation-email
	* @params: array of additional params default = empty
	* Returns: array [0]=boolean for success, [1]=message or '', @sendmail may be altered
	*/
	public function addUser($login, $password, $name, $address, &$sendmail, $params=[])
	{
		$uid = $this->db->GenID($this->pref.'module_auth_users_seq');

		if ($sendmail || $sendmail === NULL) {
			$status = $this->addRequest($login, 'activate', $sendmail, $password);
			if (!$status[0]) {
				return $status;
			}
			$isactive = 0;
		} else {
			$isactive = 1;
		}

		$funcs = new Crypter();
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
		$sql = 'INSERT INTO '.$this->pref.'module_auth_users (id,publicid,privhash,name,address,context_id,addwhen,active) VALUES (?,?,?,?,?,?,?,?)';

		if (!$this->db->Execute($sql, [$uid, $login, $password, $name, $address, $this->context, time(), $isactive])) {
			if ($sendmail) {
				$this->deleteRequest($status[1]);
			}
			return [FALSE,$this->mod->Lang('system_error', '#08')];
		}

		if (is_array($params) && count($params) > 0) {
			//TODO record supplementary data
		}

		return [TRUE, ''];
	}

	/**
	* Deletes data for @uid from all tables, if the user is not 'blocked'
	* c.f. Utils::DeleteUser, Utils::DeleteContextUsers for admin use
	* @uid: int user enumerator
	* @password: string plaintext
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function cancelUser($uid, $password)
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

		$userdata = $this->getUserBase($uid);

		if (!$userdata) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('TODO')];
		}

		if (!$this->doPasswordCheck($password, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_users WHERE id=?';

		if (!$this->db->Execute($sql, [$uid])) {
			return [FALSE,$this->mod->Lang('system_error', '#09')];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_cache WHERE user_id=?';

		if (!$this->db->Execute($sql, [$uid])) {
			return [FALSE,$this->mod->Lang('system_error', '#10')];
		}

		$parms = []; //TODO API
		$this->mod->SendEvent('OnDeregister', $parms);

		return [TRUE,$this->mod->Lang('account_deleted')];
	}

	//~~~~~~~~~~~~~ PASSWORD OPERATIONS ~~~~~~~~~~~~~~~~~

	/**
	* Gets whether password-recovery is supported
	* Returns: boolean
	*/
	public function isResettable()
	{
		return ($this->GetConfig('password_rescue') > 0);
	}

	/**
	* Allows a user to reset her/his password after requesting a reset
	* @token: string 24-byte token
	* @newpass: plaintext string
	* @repeatnewpass: plaintext string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function resetPassword($token, $newpass, $repeatnewpass)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return [FALSE,$this->mod->Lang('user_verify_failed')];
			}
		} elseif ($block_status == 'block') {
			return [FALSE,$this->mod->Lang('user_blocked')];
		}

		if (strlen($token) != 24) {
			return [FALSE,$this->mod->Lang('resetkey_invalid')];
		}

		$data = $this->getRequest($token, 'reset');

		if (!$data[0]) {
			return $data;
		}

		$status = $this->matchPassword($data['uid'], $newpass);

		if (!$status[0]) {
			return $status;
		}

		if ($newpass !== $repeatnewpass) {
			// Passwords don't match
			return [FALSE,$this->mod->Lang('newpassword_nomatch')];
		}

		$userdata = $this->getUserBase($data['uid']);

		if (!$userdata) {
			$this->AddAttempt();
			$this->deleteRequest($token);
			return [FALSE,$this->mod->Lang('system_error', '#12')];
		}

		if ($this->doPasswordCheck($newpass, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('newpassword_match')];
		}

		$newpass = password_hash($newpass, PASSWORD_DEFAULT);
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET privhash=? WHERE id=?';
		$res = $this->db->Execute($sql, [$newpass, $data['uid']]);

		if ($res) {
			$this->deleteRequest($token);
			return [TRUE,$this->mod->Lang('password_reset')];
		}
		return [FALSE,$this->mod->Lang('system_error', '#13')];
	}

	/**
	* Changes a user's password
	* @uid: int user enumerator
	* @password: plaintext string current password
	* @newpass: plaintext string
	* @repeatnewpass: plaintext string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function changePassword($uid, $password, $newpass, $repeatnewpass)
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

		$status = $this->validatePassword($newpass);

		if (!$status[0]) {
			return $status;
		} elseif ($newpass !== $repeatnewpass) {
			return [FALSE,$this->mod->Lang('newpassword_nomatch')];
		}

		$userdata = $this->getUserBase($uid);

		if (!$userdata) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('system_error', '#14')];
		}

		if (!$this->doPasswordCheck($password, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE,$this->mod->Lang('password_incorrect')];
		}

		$newpass = password_hash($newpass, PASSWORD_DEFAULT);

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET privhash=? WHERE id=?';
		$this->db->Execute($sql, [$newpass, $uid]);
		return [TRUE,$this->mod->Lang('password_changed')];
	}

	/**
	* Compares @password with the password recorded for @uid
	* Unlike matchPassword, this returns boolean and without delay on mismatch
	* @uid: int user enumerator
	* @password: plaintext string
	* Returns: boolean indicating match
	*/
	public function comparePasswords($uid, $password)
	{
		$sql = 'SELECT privhash FROM '.$this->pref.'module_auth_users WHERE id=?';
		$hash = $this->db->GetOne($sql, [$uid]);
		if ($hash) {
			return $this->doPasswordCheck($password, $hash, 0);
		}
		return FALSE;
	}

	/**
	* Verifies that @password is valid for @uid
	* @uid: int user enumerator
	* @password: plaintext string
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	protected function matchPassword($uid, $password)
	{
		$sql = 'SELECT privhash FROM '.$this->pref.'module_auth_users WHERE id=?';
		$hash = $this->db->GetOne($sql, [$uid]);
		if (!$hash) {
			return [FALSE,$this->mod->Lang('system_error', '#15')];
		}

		if (!$this->doPasswordCheck($password, $hash/*, $tries TODO*/)) {
			return [FALSE,$this->mod->Lang('password_notvalid')];
		}
		return [TRUE,''];
	}

	/**
	Checks whether @passwd matches @hash

	@password: string the password to verify
	@hash: string the hash to verify against
	@tries: no. of verification attempts, may be 0 in which case immediate return on mismatch
	Returns: boolean
	*/
	public function doPasswordCheck($password, $hash, $tries=1)
	{
		if (password_verify($password, $hash)) {
			return TRUE;
		}
		$t = min(2000, $tries * 500);
		if ($t > 0) {
			usleep($t * 1000);
		}
		return FALSE;
	}
}
