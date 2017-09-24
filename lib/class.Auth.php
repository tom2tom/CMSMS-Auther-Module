<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Inspired somewhat by PHPAuth <https://www.phpclasses.org/package/9887-PHP-Register-and-publicid-users-stored-in-a-database.html>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
# Requires PHP 5.4+
#----------------------------------------------------------------------
namespace Auther;

/* Auth ancestor-calls
Session
AddAttempt();  by Challenge too
GetConfig();  & chall
GetStatus();  & chall
UniqueToken();  & chall

AddSession();
CurrentSession();
DeleteSession();
GetIp();
MakeSourceSession();
MakeUserSession();
*/

class Auth extends Session
{
	const PATNEMAIL = '/^\S+@[^\s.]+\.\S+$/';
	const PATNPHONE = '/^(\+\d{1,4} *)?[\d ]{5,15}$/';
	const NAMEDIR = 'usernames'; //subdir name
	const PHRASEDIR = 'phrases';

	public $loginisemail;
	public $addressisemail;
	protected $trainers = ['big.txt', 'good.txt', 'bad.txt', 'matrix.txt'];
	protected $namepath;
	protected $phrasepath;
	protected $nametrained = FALSE;
	protected $phrasetrained = FALSE;

	public function __construct($mod = NULL, $context = 0)
	{
		if ($mod == NULL) {
			$mod = \cms_utils::get_module('Auther');
		}
		parent::__construct($mod, $context);
		if (!function_exists('password_hash')) {
			include __DIR__.DIRECTORY_SEPARATOR.'password.php';
		}
	}

	//~~~~~~~~~~~~~ PROPERTY VALIDATION ~~~~~~~~~~~~~~~~~

	/**
	 * Verifies that @login is an acceptable login identifier (format and not duplicated)
	 *
	 * @login: string plaintext user identifier
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ValidateLogin($login)
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
				return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('title_email'))];
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
					return [FALSE, $this->mod->Lang('email_banned')];
				}
			}
		} else {
			$this->loginisemail = FALSE;
		}
		return [TRUE, ''];
	}

	/**
	 * Verifies that @login is not duplicated
	 *
	 * @login: string plaintext user identifier
	 * @except optional string identifier to exclude from the check (normally
	 *  a current login still being used, default = FALSE
	 * @explicit: optional boolean whether to report login-is-taken or just invalid, default = FALSE
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function UniqueLogin($login, $except = FALSE, $explicit = FALSE)
	{
		if ($login !== $except || $login == FALSE) {
			$sql = 'SELECT 1 FROM '.$this->pref.'module_auth_users WHERE acchash=? AND context_id=?';
			$cfuncs = new Crypter($this->mod);
			$hash = $cfuncs->hash_value($login);
			if ($this->db->GetOne($sql, [$hash, $this->context])) {
				$msg = ($explicit) ?
					$this->mod->Lang('login_taken') :
					$this->mod->Lang('invalid_type', $this->mod->Lang('title_login'));
				return [FALSE, $msg];
			}
		}
		return [TRUE, ''];
	}

	/**
	 * Verifies (somewhat slowly) that (english-language) @login is not 'gibberish'
	 *
	 * @login: string plaintext user identifier
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function SensibleLogin($login)
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
				return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('title_login'))];
			}
		}
		return [TRUE, ''];
	}

	/**
	 * Verifies that @password respects security requirements
	 *
	 * @password: plaintext string
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ValidatePassword($password)
	{
		$val = (int)$this->GetConfig('password_min_length');
		if ($val > 0 && strlen($password) < $val) {
			return [FALSE, $this->mod->Lang('password_short')];
		}
		$funcs = new Auther\ZxcvbnPhp\Zxcvbn();
		$check = $funcs->passwordStrength($password);

		$val = (int)$this->GetConfig('password_min_score');
		if ($check['score'] + 1 < $val) { //returned value 0..4, public uses 1..5
			return [FALSE, $this->mod->Lang('password_weak')];
		}
		return [TRUE, ''];
	}

	/**
	 * Verifies that @name is an acceptable user-name
	 *
	 * @name: string
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ValidateName($name)
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
	 * Verifies (somewhat slowly) that (english-language) @name is not 'gibberish'
	 *
	 * @name: string
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function SensibleName($name)
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
			$val = Gibberish::test($name, $fp, FALSE); //TODO get & evaluate raw score
			if (!$val) {
				return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('name'))];
			}
		}
		return [TRUE, ''];
	}

	/**
	 * Verifies that @address is an acceptable contact address
	 * Must be called *after* login is validated
	 *
	 * @address: string
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ValidateAddress($address)
	{
		$val = $this->GetConfig('address_required');
		if ($val && !$address) {
			return [FALSE, $this->mod->Lang('missing_address')];
		}
		$val = $this->GetConfig('email_required');
		if ($val) {
			$res = $this->ValidateEmail($address);
			$this->addressisemail = $res[0];
			if (!$res[0] && empty($this->loginisemail)) {
				return [FALSE, $res[1]];
			}
		}
		return [TRUE, ''];
	}

	/**
	 * Verifies that @email is an acceptable email address
	 *
	 * @email: string
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ValidateEmail($email)
	{
		if (!$email || !preg_match(self::PATNEMAIL, $email)) {
			return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('title_email'))];
		}
		//always check for ban
		$parts = explode('@', $email);
		$bannedDomains = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
		if (in_array(strtolower($parts[1]), $bannedDomains)) {
			return [FALSE, $this->mod->Lang('email_banned')];
		}
		return [TRUE, ''];
	}

	/**
	 * Verifies that all @params are acceptable
	 *
	 * @params: associative array with members 'account','password' and optionally 'name' and/or 'address'
	 * @except optional string identifier passed to UniqueLogin(), default = FALSE
	 * @explicit: optional boolean passed to UniqueLogin(), default = FALSE
	 * Returns: array [0]=boolean for success, [1]=message
	 *  (possibly multi-line with embedded newlines) or ''
	 */
	public function ValidateAll($params, $except = FALSE, $explicit = FALSE)
	{
		extract($params);
		$errs = [];
		if (isset($account)) {
			$res = $this->ValidateLogin($account);
			if (!$res[0]) {
				$errs[] = $res[1];
			}
			$res = $this->UniqueLogin($account, $except, $explicit);
			if (!$res[0]) {
				$errs[] = $res[1];
			}
		}
		if (isset($password)) {
			$res = $this->ValidatePassword($password);
			if (!$res[0]) {
				$errs[] = $res[1];
			}
		}
		if (isset($name)) {
			$res = $this->ValidateName($name);
			if (!$res[0]) {
				$errs[] = $res[1];
			}
		}
		if (isset($address)) {
			$res = $this->ValidateAddress($address);
			if (!$res[0]) {
				$errs[] = $res[1];
			}
		}
		if ($errs) {
			return [FALSE, implode(PHP_EOL, $errs)];
		}
		return [TRUE, ''];
	}

	//~~~~~~~~~~~~~ PASSWORD OPERATIONS ~~~~~~~~~~~~~~~~~

	/**
	 * Generate hash for @password
	 * @password: plaintext string
	 * Returns: string
	 */
	public function HashPassword($password)
	{
		$password = substr($password, 0, 32);
		$salt = $this->UniqueToken(8, TRUE);
		return password_hash($password.$salt,PASSWORD_DEFAULT).$salt;
	}

	/**
	 * Gets whether password-recovery is supported
	 *
	 * Returns: boolean
	 */
	public function IsRecoverable()
	{
		return ($this->GetConfig('password_rescue') > 0);
	}

	/**
	 * Set new password for @uid
	 * @uid: int user enumerator
	 * @newpass: plaintext string
	 * @raw: optional boolean, whether @newpass is already hashed, default FALSE
	 * Returns: 2-member array, [0]=boolean indicating success, [1]=message
	 */
	public function ChangePasswordReal($uid, $newpass, $raw = FALSE)
	{
		if (!$raw) {
			$newpass = $this->HashPassword($newpass);
		}
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
		$this->db->Execute($sql, [$newpass, $uid]);
		if ($this->db->Affected_Rows() > 0) {
			return [TRUE, $this->mod->Lang('password_changed')];
		}
		return [FALSE, $this->mod->Lang('system_error', '#01')];
	}

	/**
	 * If action-status warrants or @check=FALSE, changes a user's password
	 *
	 * @uid: int user enumerator
	 * @password: plaintext string current password
	 * @newpass: plaintext string
	 * @repeatnewpass: plaintext string
	 * @check: optional boolean, whether to check action-status before proceeding, default = TRUE
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ChangePassword($uid, $password, $newpass, $repeatnewpass, $check = TRUE)
	{
		if ($check) {
			switch ($this->GetStatus()) {
			 case parent::STAT_BLOCK:
				return [FALSE, $this->mod->Lang('user_blocked')];
			 case parent::STAT_VERIFY:
				if (0) { //TODO FACTOR
					return [FALSE, $this->mod->Lang('user_verify_failed')];
				}
				break;
			 case parent::STAT_CHALLENGE:
				return [FALSE, $this->mod->Lang('user_challenged')];
			}
		}

		$status = $this->matchPassword($uid, $password);
		$token = FALSE; //TODO

		if (!$status[0]) {
			$this->AddAttempt($token);
			return $status;
		}

		$status = $this->ValidatePassword($newpass);

		if (!$status[0]) {
			return $status;
		} elseif ($newpass !== $repeatnewpass) {
			return [FALSE, $this->mod->Lang('newpassword_nomatch')];
		}

		$userdata = $this->GetUserBase($uid);

		if (!$userdata) {
			$this->AddAttempt($token);
			return [FALSE, $this->mod->Lang('system_error', '#02')];
		}

		$tries = 1; //TODO
		if (!$this->DoPasswordCheck($password, $userdata['password'], $tries)) { //no $uid/update yet
			$this->AddAttempt($token);
			return [FALSE, $this->mod->Lang('incorrect_type', $this->mod->Lang('password'))];
		}

		$newpass = $this->HashPassword($newpass);

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
		$this->db->Execute($sql, [$newpass, $uid]);
		return [TRUE, $this->mod->Lang('password_changed')];
	}

	/**
	 * Compares @password with the password recorded for @uid
	 * Unlike matchPassword, this returns boolean and without delay on mismatch
	 *
	 * @uid: int user enumerator
	 * @password: plaintext string
	 * Returns: boolean indicating match
	 */
	public function ComparePasswords($uid, $password)
	{
		$sql = 'SELECT passhash FROM '.$this->pref.'module_auth_users WHERE id=?';
		$hash = $this->db->GetOne($sql, [$uid]);
		if ($hash) {
			return $this->DoPasswordCheck($password, $hash, 0, $uid);
		}
		return FALSE;
	}

	/**
	 * Verifies that @password is valid for @uid
	 *
	 * @uid: int user enumerator
	 * @password: plaintext string
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	protected function MatchPassword($uid, $password)
	{
		$sql = 'SELECT passhash FROM '.$this->pref.'module_auth_users WHERE id=?';
		$hash = $this->db->GetOne($sql, [$uid]);
		if (!$hash) {
			return [FALSE, $this->mod->Lang('system_error', '#03')];
		}

		$tries = 1; //TODO
		if (!$this->DoPasswordCheck($password, $hash, $tries, $uid)) {
			return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('password'))];
		}
		return [TRUE, ''];
	}

	/**
	 * Checks whether @passwd matches @hash
	 *
	 * @password: string the password to verify
	 * @hash: string the hash to verify against
	 * @tries: optional no. of verification attempts, may be 0 in which case immediate return on mismatch, default = 1
	 * @uid: optional user-identifier > 0 for password re-hash if needed, default 0
	 * Returns: boolean
	 */
	public function DoPasswordCheck($password, $hash, $tries = 1, $uid = 0)
	{
		$password = substr($password, 0, 32);
		$salt = substr($hash, -8);
/*		if (extension_loaded('mbstring')) {
			$len = mb_strlen($password, '8bit');
		} else {
			$len = strlen($password);
		}
*/
		$len = strlen(bin2hex($hash))/2; //raw strlen may return chars
		$hash = substr($hash, 0, $len-8);
		if (password_verify($password.salt, $hash)) {
			if ($uid > 0 && password_needs_rehash($hash, PASSWORD_DEFAULT)) {
				$newhash = $this->HashPassword($password);
				$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
				$this->db->Execute($sql, [$newhash, $uid]);
			}
			return TRUE;
		}
		$t = min(2000, $tries * 500);
		if ($t > 0) {
			usleep($t * 1000);
		}
		return FALSE;
	}

	//~~~~~~~~~~~~~ SESSION ~~~~~~~~~~~~~~~~~

	/**
	 * Logs a user in
	 *
	 * @login: string plaintext user identifier
	 * @password: plaintext string
	 * @remember: optional boolean whether to setup session-expiry-time in self::AddSession() default = FALSE
	 * Returns: array, [0]=boolean for success, [1]=message or '', if [0] then also session-parameters: 'token','expire'
	 */
	public function Login($login, $password, $remember = FALSE)
	{
		//always check status
		switch ($this->GetStatus()) {
		 case parent::STAT_BLOCK:
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE, $this->mod->Lang('user_blocked')];
		 case parent::STAT_CHALLENGE:
			return [FALSE, $this->mod->Lang('user_challenged')];
		 case parent::STAT_VERIFY:
			if (0) { //TODO FACTOR
				$parms = []; //TODO API
				$this->mod->SendEvent('OnLoginFail', $parms);
				return [FALSE, $this->mod->Lang('user_verify_failed')];
			}
			break;
		}

		$uid = $this->GetUserID($login);
		$token = FALSE; //TODO

		if (!$uid) {
			$this->AddAttempt($token);
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE, $this->mod->Lang('incorrect_type', $this->mod->Lang('title_login'))];
		}

		$userdata = $this->GetUserBase($uid);

		if (!$userdata['active']) {
			$this->AddAttempt($token);
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE, $this->mod->Lang('account_inactive')];
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->AddAttempt($token);
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE, $this->mod->Lang('incorrect_type', $this->mod->Lang('password'))];
		}

		if (!is_bool($remember)) {
			$this->AddAttempt($token);
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('rememberme'))];
		}

		$sdata = $this->AddSession($uid, $token, $remember);

		if (!$sdata) {
			$parms = []; //TODO API
			$this->mod->SendEvent('OnLoginFail', $parms);
			return [FALSE, $this->mod->Lang('system_error', '#04')];
		}

		$parms = []; //TODO API
		$this->mod->SendEvent('OnLogin', $parms);

		$data = [TRUE, $this->mod->Lang('logged_in')];
		$data['token'] = $sdata['token'];
		$data['expire'] = $sdata['expiretime'];
		return $data;
	}

	/**
	 * Ends the session identified by @token
	 *
	 * @token: string 24-byte session-identifier
	 * Returns: boolean
	 */
	public function Logout($token)
	{
		if (strlen($token) != 24) {
			return FALSE;
		}
		return $this->DeleteSession($token);
	}

	//~~~~~~~~~~~~~ USER OPERATIONS ~~~~~~~~~~~~~~~~~

	/**
	 * Checks whether @login is recorded for current context and (if @active = TRUE)
	 *  active, and @password (if not FALSE) is valid. As distinct from IsRegistered(),
	 *  no session is involved, and no delay. Sorta 'IsRegisteredReal'
	 *
	 * @login: string plaintext user identifier
	 * @password: optional plaintext string, or FALSE to skip password-validation, default = FALSE
	 * @active: optional boolean whether to check for active user, default TRUE
	 * Returns: boolean indicating success
	 * TODO also return indication that password-reset is now forced
	 */
	public function IsKnown($login, $password = FALSE, $active = TRUE)
	{
		$uid = $this->GetUserID($login);
		if ($uid) {
			$userdata = $this->GetUserBase($uid);
			if ($userdata) {
				if ($password && !$this->ComparePasswords($uid, $password)) {
					return FALSE;
				}
				if ($active && !$userdata['active']) {
					return FALSE;
				}
				return TRUE;
			}
		}
		return FALSE;
	}

	/**
	 * Checks whether @login is recorded for current context and (if @active = TRUE)
	 *  active, and @password (if not FALSE) is valid. A session is created/updated
	 *  as appropriate.
	 *
	 * @login: string plaintext user identifier
	 * @password: optional plaintext string, or FALSE to skip password-validation, default = FALSE
	 * @active: optional boolean whether to check for active user, default TRUE
	 * @fast: optional boolean whether to return immediately if not recognized, default = FALSE
	 * @token: optional string 24-byte session-data key, default = FALSE
	 * Returns: 2-member array, [0]=boolean indicating success [1]=array of data from row of users-table
	 * TODO also return indication that password-reset is now forced
	 */
	public function IsRegistered($login, $password = FALSE, $active = TRUE, $fast = FALSE, $token = FALSE)
	{
		$sql = 'SELECT id,passhash,active FROM '.$this->pref.'module_auth_users WHERE acchash=? AND context_id=?';
		$cfuncs = new Crypter($this->mod);
		$hash = $cfuncs->hash_value($login);
		$userdata = $this->db->GetRow($sql, [$hash, $this->context]);
		$uid = ($userdata) ? $userdata['id'] : -1;
		$ip = $this->GetIp();
		$sdata = $this->CurrentSession($token, $uid, $ip);
		if ($userdata && (!$active || $userdata['active'] > 0)) {
			if ($password === FALSE) {
				if ($sdata) {
					//cleanup TODO change status if NEW_FOR_IP
					$sql = 'UPDATE '.$this->pref.'module_auth_cache SET user_id=?,attempts=1 WHERE token=?';
					$this->db->Execute($sql, [$uid, $token]); //TODO update token WHERE token=sdata[token]
					$sdata['user_id'] = $uid;
					$sdata['attempts'] = 1;
				} else {
					$token = $this->MakeUserSession($uid, $token);
					$sql = 'SELECT * FROM '.$this->pref.'module_auth_cache WHERE token=?';
					$sdata = $this->db->GetRow($sql, [$token]);
				}
				return [TRUE, $sdata];
			}
			if (!$sdata) {
				$token = $this->MakeUserSession($uid, $token);
				$sql = 'SELECT * FROM '.$this->pref.'module_auth_cache WHERE token=?';
				$sdata = $this->db->GetRow($sql, [$token]);
			}
			$tries = ($fast) ? 0 : $sdata['attempts'];
			$res = $this->DoPasswordCheck($password, $userdata['passhash'], $tries, $uid);
			if (!$res) {
				$this->AddAttempt($sdata['token']); //TODO update token WHERE token=sdata[token]
				++$sdata['attempts'];
			}
			return [$res, $sdata];
		} else {
			if ($sdata) {
				$this->AddAttempt($sdata['token']);
				++$sdata['attempts'];
			} else {
				$token = $this->MakeSourceSession($ip, $token);
				$sql = 'SELECT * FROM '.$this->pref.'module_auth_cache WHERE token=?';
				$sdata = $this->db->GetRow($sql, [$token]);
			}
		}
		if (!$fast) {
			$times = isset($sdata['attempts']) ? $sdata['attempts'] : 1;
			$t = min(2000, $times * 500);
			usleep($t * 1000);
		}
		return [FALSE, $sdata];
	}

	/**
	 * If action-status warrants or @check=FALSE, changes a user's login name
	 *
	 * @uid: int user enumerator
	 * @login: string plaintext user identifier
	 * @password: plaintext string
	 * @check: optional boolean, whether to check action-status before proceeding, default = TRUE
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ChangeLogin($uid, $login, $password, $check = TRUE)
	{
		if ($check) {
			switch ($this->GetStatus()) {
			 case parent::STAT_BLOCK:
				return [FALSE, $this->mod->Lang('user_blocked')];
			 case parent::STAT_CHALLENGE:
				return [FALSE, $this->mod->Lang('user_challenged')];
			 case parent::STAT_VERIFY:
				if (0) { //TODO
					return [FALSE, $this->mod->Lang('user_verify_failed')];
				}
				break;
			}
		}

		$status = $this->ValidateLogin($login);

		if (!$status[0]) {
			return $status;
		}

		$status = $this->matchPassword($uid, $password);

		if (!$status[0]) {
			$this->AddAttempt($token);
			return $status;
		}

		$userdata = $this->GetUserBase($uid);

		if (!$userdata) {
			$this->AddAttempt($token);
			return [FALSE, $this->mod->Lang('system_error', '#05')];
		}

		$tries = 1; //TODO
		if (!$this->DoPasswordCheck($password, $userdata['password'], $tries, $uid)) {
			$this->AddAttempt($token);
			return [FALSE, $this->mod->Lang('incorrect_type', $this->mod->Lang('password'))];
		}

		if ($login == $userdata['account']) {
			$this->AddAttempt($token);
			return [FALSE, $this->mod->Lang('newlogin_match')];
		}

		$cfuncs = new Crypter($this->mod);
		$hash = $cfuncs->hash_value($login);
		$login = $cfuncs->cloak_value($login, 16);
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET account=?,acchash=? WHERE id=?';
		$this->db->Execute($sql, [$login, $hash, $uid]);
		if ($this->db->Affected_Rows() > 0) {
			return [TRUE, $this->mod->Lang('login_changed')];
		}
		return [FALSE, $this->mod->Lang('system_error', '#06')];
	}

	/**
	 * Get a variant of (non-email) @login which is not currently recorded
	 *
	 * @login: string plaintext user identifier
	 * Returns: string, @login with a numeric suffix, or @login, or FALSE
	 */
	public function NumberedLogin($login)
	{
		if (!login || preg_match(self::PATNEMAIL, $login)) {
			return FALSE;
		}
		$sql = 'SELECT account FROM '.$this->pref.'module_auth_users WHERE context_id=?';
		$data = $this->db->GeCol($sql, [$this->context]);
		if ($data) {
			$cfuncs = new Crypter($this->mod);
			$mpw = $cfuncs->decrypt_preference(Crypter::MKEY);
			$suffs = [];
			$pl = strlen($login);
			foreach ($data as $one) {
				$t = $cfuncs->uncloak_value($one, $mpw);
				if (strncmp($t, $login, $pl) === 0) {
					$s = substr($t, $pl);
					if ($s && is_numeric($s)) {
						$suffs[] = (int)$s;
					}
				}
			}
			foreach ($suffs as $i => $one) {
				if (isset($suffs[$i + 1])) {
					if ($suffs[$i + 1] - $one > 1) {
						$s = $one + 1;
						return $login.$s;
					}
				}
			}
			$s = count($suffs) + 1;
			return $login.$s;
		}
		return $login;
	}

	/**
	 * Gets all user-data except password for @uid
	 *
	 * @uid: int user enumerator
	 * @raw: optional boolean, whether to decrypt relevant values, default = FALSE
	 * Returns: array with members uid,account,name,address,context_id,addwhen,lastuse,nameswap,active or else FALSE
	 */
	public function GetUser($uid, $raw = FALSE)
	{
		$sql = 'SELECT * FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql, [$uid]);

		if ($data) {
			unset($data['id']);
			unset($data['passhash']);
			if (!$raw) {
				$cfuncs = new Crypter($this->mod);
				$data['account'] = $cfuncs->uncloak_value($data['account']);
				$data['name'] = $cfuncs->uncloak_value($data['name']);
				$data['address'] = $cfuncs->uncloak_value($data['address']);
//TODO context ??
				$dt = new \DateTime('@0', NULL);
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
	 *
	 * @uid: int user enumerator
	 * @raw: optional boolean, whether to encode the value, default = FALSE
	 * Returns: string, raw or H-packed password, or else FALSE
	 */
	public function GetUserPassword($uid, $raw = FALSE)
	{
		$sql = 'SELECT passhash FROM '.$this->pref.'module_auth_users WHERE id=?';
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
	 * Get user-enumerator(s) for @login (whether or not currently active)
	 *
	 * @login: string plaintext user/account identifier, or array of them
	 * Returns: enumerator or associative array or FALSE
	 */
	public function GetUserID($login)
	{
		$a = is_array($login);
		if ($a) {
			$ret = [];
		} else {
			$ret = FALSE;
			$login = [$login];
		}

		$cfuncs = new Crypter($this->mod);
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE acchash=? AND context_id=?';
		foreach($login as $one) {
			$hash = $cfuncs->hash_value($one);
			$uid = $this->db->GetOne($sql, [$hash, $this->context]);
			if ($uid) {
				if ($a) {
					$ret[$one] = (int)$uid;
				} else {
					return (int)$uid;
				}
			}
		}
		return $ret;
	}

	/**
	 * Gets some user-data for @uid
	 *
	 * @uid: int user enumerator
	 * Returns: array with members uid,account,passhash(raw),active or else FALSE
	 */
	protected function GetUserBase($uid)
	{
		$sql = 'SELECT account,passhash,active FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql, [$uid]);

		if ($data) {
			$data['uid'] = $uid;
			$cfuncs = new Crypter($this->mod);
			$data['account'] = $cfuncs->uncloak_value($data['account']);
			return $data;
		}
		return FALSE;
	}

	/**
	 * Gets publicly-accessible user-data for @login
	 *
	 * @login: string plaintext user identifier
	 * @active: optional boolean, whether the user is required to be active, default = TRUE
	 * Returns: array with members account,name,address,addwhen,lastuse[,active] or else FALSE
	 */
	public function GetUserPublic($login, $active = TRUE)
	{
		$sql = 'SELECT name,address,addwhen,lastuse';
		if (!$active) {
			$sql .= ',active';
		}
		$sql .= ' FROM '.$this->pref.'module_auth_users WHERE acchash=? AND context_id=?';
		if ($active) {
			$sql .= ' AND active>0';
		}
		$cfuncs = new Crypter($this->mod);
		$mpw = $cfuncs->decrypt_preference(Crypter::MKEY);
		$hash = $cfuncs->hash_value($login, $mpw);
		$data = $this->db->GetRow($sql, [$hash, $this->context]);

		if ($data) {
			$data['account'] = $login;
			$data['name'] = $cfuncs->uncloak_value($data['name'], $mpw);
			$data['address'] = $cfuncs->uncloak_value($data['address'], $mpw);
//TODO zone offset
			$dt = new \DateTime('@0', NULL);
			$dt->setTimestamp($data['addwhen']);
			$data['addwhen'] = $dt->format('Y-m-d H:i:s');
			$dt->setTimestamp($data['lastuse']);
			$data['lastuse'] = $dt->format('Y-m-d H:i:s');
			return $data;
		}
		return FALSE;
	}

	/**
	 * Gets specified user-data for @login
	 *
	 * @login: string plaintext user identifier, or array of them
	 * @props: optional string, table field-name, or '*' or array of field names, default = '*'
	 * @active: optional boolean, whether the user(s) is/are required to be active, default = TRUE
	 * Returns: associative array or else FALSE
	 */
	public function GetUserProperties($login, $props = '*', $active = TRUE)
	{
		if (is_array($props)) {
			$namers = implode(',', $props);
		} elseif ($props == '*') {
			$namers = 'id,account,name,address,addwhen,lastuse,nameswap,active'; //exclude a few of the fields
		} else {
			$namers = $props;
		}
		if (strpos($namers,'account') === FALSE) {
			$namers = 'account,'.$namers;
			$strip = TRUE;
		} else {
			$strip = FALSE;
		}
		$sql = 'SELECT '.$namers.' FROM '.$this->pref.'module_auth_users WHERE context_id=?';
		if ($active) {
			$sql .= ' AND active>0';
		}
		$data = $this->db->GetArray($sql, [$this->context]);

		if ($data) {
			$cfuncs = new Crypter($this->mod);
			$mpw = $cfuncs->decrypt_preference(Crypter::MKEY);
			$dt = new \DateTime('@0', NULL);
//TODO zone offset
			$a = is_array($login);
			$ret = [];
			foreach ($data as $one) {
				$t = $cfuncs->uncloak_value($one['account'], $mpw);
				if ((!$a && $t == $login) || ($a && in_array($t,$login))) {
					if ($strip) {
						unset($one['account']);
					} else {
						$one['account'] = $t;
					}
					if (!empty($one['name'])) {
						$one['name'] = $cfuncs->uncloak_value($one['name'], $mpw);
					}
					if (!empty($one['address'])) {
						$one['address'] = $cfuncs->uncloak_value($one['address'], $mpw);
					}
					if (!empty($one['addwhen'])) {
						$dt->setTimestamp($one['addwhen']);
						$one['addwhen'] = $dt->format('Y-m-d H:i:s');
					}
					if (!empty($one['lastuse'])) {
						$dt->setTimestamp($one['lastuse']);
						$one['lastuse'] = $dt->format('Y-m-d H:i:s');
					}
					$ret[] = $one;
				}
			}
			return $ret;
		}
		return FALSE;
	}

	/**
	 * Converts relevant members of @data to UI-ready form
	 *
	 * @data reference to associative array, each member like users-table-fieldname=>rawval,
	 * or an array of such arrays
	 */
	public function GetPlainUserProperties(&$data)
	{
		reset($data);
		if (is_numeric(key($data))) {
			$cfuncs = new Crypter($this->mod);
			$dt = new \DateTime('@0', NULL);
			foreach ($data as &$one) {
				foreach ($one as $name => &$val) {
					switch ($name) {
					 case 'account':
					 case 'name':
					 case 'address':
						$val = $cfuncs->uncloak_value($val);
						break;
					 case 'addwhen':
					 case 'lastuse':
						$dt->setTimestamp($val);
						$val = $dt->format('Y-m-d H:i:s');
						break;
					 default:
						if (is_numeric($val)) {
							$val += 0;
						} elseif (is_string($val)) {
							$val = trim($val);
						}
					}
				}
				unset ($val);
			}
			unset ($one);
		} else { //single row of data
			$cfuncs = NULL;
			$dt = NULL;
			foreach ($data as $name => &$val) {
				switch ($name) {
				 case 'account':
				 case 'name':
				 case 'address':
					if (!$cfuncs) {
						$cfuncs = new Crypter($this->mod);
					}
					$val = $cfuncs->uncloak_value($val);
					break;
				 case 'addwhen':
				 case 'lastuse':
					if (!$dt) {
						$dt = new \DateTime('@0', NULL);
					}
					$dt->setTimestamp($val);
					$val = $dt->format('Y-m-d H:i:s');
					break;
				 default:
					if (is_numeric($val)) {
						$val += 0;
					} elseif (is_string($val)) {
						$val = trim($val);
					}
				}
			}
			unset ($val);
		}
	}

	/**
	 * Gets locally-hashed value of @str
	 *
	 * @str:
	 * @raw: optional boolean whether to get binary-hash, default TRUE
	 * Returns: string
	 */
	public function GetHash($str, $raw = TRUE)
	{
		$cfuncs = new Crypter($this->mod);
		return $cfuncs->hash_value($one, FALSE, $raw);
	}

	/**
	 * Gets some data for all active users of the current context
	 *
	 * Returns: associative array, each member of which is uid=>login, or else FALSE
	 */
	public function GetActiveUsers()
	{
		$sql = 'SELECT id,account FROM '.$this->pref.'module_auth_users WHERE context_id=? AND active>0 ORDER BY addwhen';
		$data = $this->db->GetAssoc($sql, [$this->context]);
		if ($data) {
			$cfuncs = new Crypter($this->mod);
			$mpw = $cfuncs->decrypt_preference(Crypter::MKEY);
			foreach ($data as &$one) {
				$one = $cfuncs->uncloak_value($one, $mpw);
			}
			unset ($one);
		}
		return $data;
	}

	/**
	 * Gets some specific data for all, or all active, users of the current context
	 *
	 * @active: optional boolean, whether to report for active-users only, default = TRUE
	 * @raw: optional boolean, whether to return encrypted data as-is, default = FALSE
	 * Returns: array, each member of which has user_id,account,name,address,nameswap or else FALSE
	 */
	public function GetPublicUsers($active = TRUE, $raw = FALSE)
	{
		$sql = 'SELECT id,account,name,address,nameswap FROM '.$this->pref.'module_auth_users WHERE context_id=?';
		if ($active) {
			$sql .= ' AND active>0';
		}
		$data = $this->db->GetArray($sql, [$this->context]);
		if ($data) {
			if (!$raw) {
				$cfuncs = new Crypter($this->mod);
				$mpw = $cfuncs->decrypt_preference(Crypter::MKEY);
				foreach ($data as &$one) {
					$one['account'] = $cfuncs->uncloak_value($one['account'], $mpw);
					$one['name'] = $cfuncs->uncloak_value($one['name'], $mpw);
					$one['address'] = $cfuncs->uncloak_value($one['address'], $mpw);
				}
				unset ($one);
				//TODO support mb sort
				usort($data, function ($a, $b) { return strcmp($a['account'], $b['account']); });
			}
		}
		return $data;
	}

	/**
	 * Records a new user, without any status-check or parameter validation
	 *
	 * @login: string plaintext user identifier
	 * @password: plaintext string
	 * @name: string user name
	 * @address: email or other type of address for messages, possibly empty
	 * @active: optional integer (1/0) indicating user's active-state, default = 1
	 * @params: optional array of additional params, default = empty
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function AddUserReal($login, $password, $name, $address, $active = 1, $params = [])
	{
		$uid = $this->db->GenID($this->pref.'module_auth_users_seq');

		$password = $this->HashPassword($password);

		$cfuncs = new Crypter($this->mod);
		$hash = $cfuncs->hash_value($login);
		$login = $cfuncs->cloak_value($login, 16);
		if ($name || is_numeric($name)) {
			$name = $cfuncs->cloak_value($name);
		} else {
			$name = NULL;
		}
		if ($address || is_numeric($address)) {
			$address = $cfuncs->cloak_value($address, 24);
		} else {
			$address = NULL;
		}
		//TODO any others?
		$sql = 'INSERT INTO '.$this->pref.'module_auth_users (id,account,acchash,passhash,name,address,context_id,addwhen,active) VALUES (?,?,?,?,?,?,?,?)';
		$this->db->Execute($sql, [$uid, $login, $hash, $password, $name, $address, $this->context, time(), $active]);
		if ($this->db->Affected_Rows() == 0) {
			return [FALSE, $this->mod->Lang('system_error', '#07')]; //probably a duplicate
		}

		if (is_array($params) && count($params) > 0) {
			//TODO record supplementary data
		}

		return [TRUE, ''];
	}

	/**
	 * If action-status warrants or @check=FALSE, creates and records a new user,
	 *  after parameter validation
	 *
	 * @login: string plaintext user identifier
	 * @password: plaintext string
	 * @name: string user name
	 * @address: email or other type of address for messages, possibly empty
	 * @params: array of additional params, default = empty
	 * @check: optional boolean, whether to check action-status before proceeding, default = TRUE
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function AddUser($login, $password, $name, $address, $params = [], $check = TRUE)
	{
		if ($check) {
			switch ($this->GetStatus()) {
			 case parent::STAT_BLOCK:
				return [FALSE, $this->mod->Lang('user_blocked')];
			 case parent::STAT_CHALLENGE:
				return [FALSE, $this->mod->Lang('user_challenged')];
			}
		}

		$res = $this->ValidateAll([
			'account' => $login,
			'password' => $password,
			'name' => $name,
			'address' => $address
		]);  //NOT $except or $explicit
		if ($res[0]) {
			return $this->addUserReal($login, $password, $name, $address, 1, $params);
		}
		return $res;
	}

	/**
	 * If action-status warrants or @check=FALSE, creates and records a user,
	 *  after validation of all supplied parameters
	 *
	 * @login: string plaintext user identifier
	 * @password: plaintext string
	 * @repeatpass: plaintext string
	 * @address: plaintext string
	 * @params: optional array of extra user-parameters for self::addUser() default = empty
	 * @check: optional boolean, whether to check action-status before proceeding, default = TRUE
	 * Returns: array [0]=boolean for success, [1]=message (possibly multi-line) or ''
	 */
	public function RegisterUser($login, $password, $repeatpass, $name, $address, $params = [], $check = TRUE)
	{
		if ($password !== $repeatpass) {
			return [FALSE, $this->mod->Lang('password_nomatch')];
		}

		$res = $this->AddUser($login, $password, $name, $address, $params, $check);
		if ($res[0]) {
			$parms = []; //TODO API
			$this->mod->SendEvent('OnRegister', $parms);
			return [TRUE, $this->mod->Lang('register_success')];
		}
		return $res;
	}

	/**
	 * Changes property-values (not password) for a user, without any status-check
	 *  or parameter validation except @oldlogin must be recognised
	 *
	 * @oldlogin: string curent user identifier
	 * @login: string plaintext new user identifier, ignored if any FALSE other than '' or '0'
	 * @name: string new user name, ignored if ditto
	 * @address: string new email or other type of address for messages, ignored if ditto
	 * @active: optional flag (0/1 or FALSE) indicating user's active-state, default = FALSE
	 * @params: optional array of additional params, default = empty
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ChangeUserReal($oldlogin, $login, $name, $address, $active = FALSE, $params = [])
	{
		$uid = $this->GetUserID($oldlogin);
		if (!$uid) {
			return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('title_login'))];
		}

		$namers = [];
		$args = [];
		$cfuncs = new Crypter($this->mod);

		//TODO consider - password change too?
		if ($login && $login !== $oldlogin) {
			$namers[] = 'account';
			$args[] = $cfuncs->cloak_value($login, 16);
			$namers[] = 'acchash';
			$args[] = $cfuncs->hash_value($login);
		}
		if ($name || $name === '' || is_numeric($name)) {
			$namers[] = 'name';
			$args[] = $cfuncs->cloak_value($name);
		}
		if ($address || $address === '' || is_numeric($address)) {
			$namers[] = 'address';
			$args[] = $cfuncs->cloak_value($address, 24);
		}
		if ($active !== FALSE) {
			$namers[] = 'active';
			$args[] = $active;
		}
		$args[] = $uid;
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET '.implode('=?,', $namers).'=? WHERE id=?';
		$this->db->Execute($sql, $args);
		if ($this->db->Affected_Rows() == 0) {
			return [FALSE, $this->mod->Lang('system_error', '#08')];
		}

		if (is_array($params) && count($params) > 0) {
			//TODO record supplementary data
		}

		return [TRUE, ''];
	}

	/**
	 * If action-status warrants or @check=FALSE, changes property-values
	 *  (not password) for a user, after new-parameter validation
	 *
	 * @oldlogin: string current user plaintext identifier
	 * @password: string plaintext current password
	 * @login: string new user plaintext identifier ignored if FALSE
	 * @name: string user name maybe ignored if FALSE
	 * @address: email or other type of address for messages, ignored if FALSE
	 * @active: optional integer (0/1) or FALSE, default = FALSE
	 * @params: optional array of additional parameters, default = empty
	 * @check: optional boolean, whether to check action-status before proceeding, default = TRUE
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ChangeUser($oldlogin, $password, $login, $name, $address, $active = FALSE, $params = [], $check = TRUE)
	{
		if ($check) {
			switch ($this->GetStatus()) {
			 case parent::STAT_BLOCK:
				return [FALSE, $this->mod->Lang('user_blocked')];
			 case parent::STAT_CHALLENGE:
				return [FALSE, $this->mod->Lang('user_challenged')];
			}
		}

		$res = $this->IsRegistered($oldlogin, $password, FALSE);  //FALSE, $token);
		if (!$res[0]) {
			return $res;
		}

		if ($login === FALSE) {
			$login = $oldlogin;
		}
		$data = FALSE;
		if ($name === FALSE) {
			$data = $this->GetUserProperties($oldlogin, ['name', 'address'], FALSE);
			$name = $data['name'];
		}
		if ($address === FALSE) {
			if (!$data) {
				$data = $this->GetUserProperties($oldlogin, 'address', FALSE);
			}
			$address = $data['address'];
		}
		$res = $this->ValidateAll([
			'account' => $login,
			'password' => $password,
			'name' => $name,
			'address' => $address
		], $oldlogin); //NOT $explicit

		if ($res[0]) {
			return $this->ChangeUserReal($oldlogin, $login, $name, $address, $active, $params);
		}
		return $res;
	}

	/**
	 * Deletes data for @login from all tables, sends event
	 * c.f. Utils->DeleteUser, Utils->DeleteContextUsers for admin use
	 *
	 * @login: string plaintext user identifier
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function DeleteUserReal($login)
	{
		$uid = $this->GetUserID($login);
		if (!$uid) {
			return [FALSE, $this->mod->Lang('invalid_type', $this->mod->Lang('title_login'))];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_users WHERE id=?';
		$this->db->Execute($sql, [$uid]);
		if ($this->db->Affected_Rows() == 0) {
			return [FALSE, $this->mod->Lang('system_error', '#09')];
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_cache WHERE user_id=?';
		$this->db->Execute($sql, [$uid]);
		if ($this->db->Affected_Rows() == 0) { //TODO make it ok if no such record(s)
			return [FALSE, $this->mod->Lang('system_error', '#10')];
		}

		$parms = []; //TODO API
		$this->mod->SendEvent('OnDeregister', $parms);

		return [TRUE, ''];
	}

	/**
	 * If action-status warrants or @check=FALSE, deletes data for @login from all tables
	 *
	 * @login: string plaintext user identifier
	 * @password: string plaintext
	 * @check: optional boolean, whether to check action-status before proceeding, default = TRUE
	 * Returns: array [0]=boolean for success, [1]=message
	 */
	public function DeleteUser($login, $password, $check = TRUE)
	{
		if ($check) {
			switch ($this->GetStatus()) {
			 case parent::STAT_BLOCK:
				return [FALSE, $this->mod->Lang('user_blocked')];
			 case parent::STAT_CHALLENGE:
				return [FALSE, $this->mod->Lang('user_challenged')];
			 case parent::STAT_VERIFY:
				if (0) { //TODO FACTOR
					return [FALSE, $this->mod->Lang('user_verify_failed')];
				}
				break;
			}
		}

		$res = $this->IsRegistered($login, $password, FALSE);  // FALSE, $token);
		if ($res[0]) {
			$res = $this->DeleteUserReal($login);
			if ($res[0]) {
				return [TRUE, $this->mod->Lang('delete_success')];
			}
		}
		return $res;
	}
}
