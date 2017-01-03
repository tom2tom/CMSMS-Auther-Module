<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Adapted for CMSMS from PHPAuth <https://www.phpclasses.org/package/9887-PHP-Register-and-login-users-stored-in-a-database.html>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
# Requires PHP 5.3+
#----------------------------------------------------------------------
namespace Auther;

/* TODO
2FA support
 captcha?

CMSMailer module support
addUser() race fix
autoloading
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
	protected $mailer = NULL;

	public function __construct(&$mod, $context=NULL)
	{
		$this->mod = $mod;
		$this->db = \cmsms()->GetDb();
		$tnis->pref = \cms_db_prefix();
		$this->context = $context;

		if (version_compare(phpversion(),'5.5.0','<')) {
			require(__DIR__.DIRECTORY_SEPARATOR.'password.php');
		}
	}

	/**
	* Logs a user in
	* @login string user identifier
	* @password plaintext string
	* @remember boolean whether to setup session-expiry-time in self::addSession() default = FALSE
	* Returns: array, 0=>T/F for success, 1=>message, if success then also session-parameters: 'hash','expire'
	*/
	public function login($login, $password, $remember=FALSE)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				$this->mod->SendEvent('OnLoginFail',$parms);
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			$this->mod->SendEvent('OnLoginFail',$parms);
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$uid = $this->getUID($login);

		if (!$uid) {
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail',$parms);
			return array(FALSE,$this->mod->Lang('login_incorrect'));
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata['isactive']) {
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail',$parms);
			return array(FALSE,$this->mod->Lang('account_inactive'));
		}

		$status = $this->matchPassword($uid,$password);

		if (!$status[0]) {
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail',$parms);
			return array(FALSE,$this->mod->Lang('password_incorrect'));
		}

		if (!is_bool($remember)) {
			$this->addAttempt();
			$this->mod->SendEvent('OnLoginFail',$parms);
			return array(FALSE,$this->mod->Lang('remember_me_invalid'));
		}

		$sessiondata = $this->addSession($uid,$remember);

		if (!$sessiondata) {
			$this->mod->SendEvent('OnLoginFail',$parms);
			return array(FALSE,$this->mod->Lang('system_error').' #01');
		}

		$this->mod->SendEvent('OnLogin',$parms);

		$data = array(TRUE,$this->mod->Lang('logged_in'));
		$data['hash'] = $sessiondata['hash'];
		$data['expire'] = $sessiondata['expiretime'];
		return $data;
	}

	/**
	* Creates and records a user
	* @login string user identifier
	* @password plaintext string
	* @repeatpassword plaintext string
	* @email email address for notices to the user default = ''
	* @params array extra user-parameters for self::addUser() default = empty
	* @sendmail bool whether to send email-messages if possible default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function register($login, $password, $repeatpassword, $email='', $params=array(), $sendmail=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO FACTOR
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		// Validate login
		$status = $this->validateLogin($login);
		if (!$status[0]) {
			return $status;
		}

		if ($this->isLoginTaken($login)) {
			return array(FALSE,$this->mod->Lang('login_taken'));
		}

		// Validate password
		$status = $this->validatePassword($password);
		if (!$status[0]) {
			return $status;
		}

		if ($password !== $repeatpassword) {
			return array(FALSE,$this->mod->Lang('password_nomatch'));
		}

		if ($email) {
			// Validate email
			$status = $this->validateEmail($email);
			if (!$status[0]) {
				return $status;
			}
		}

		$status = $this->addUser($login,$password,$email,$sendmail,$params);
		if (!$status[0]) {
			return $status;
		}

		$this->mod->SendEvent('OnRegister',$parms);

		$msg = ($sendmail) ?
		 $this->mod->Lang('register_success') :
		 $this->mod->Lang('register_success_message_suppressed');
		return array(TRUE,$msg);
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
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		if (strlen($key) !== 32) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('activationkey_invalid'));
		}

		$data = $this->getRequest($key,'activate');

		if (!$data[0]) {
			$this->addAttempt();
			return $data;
		}

		$userdata = $this->getBaseUser($data['uid']);
		if ($userdata['isactive']) {
			$this->addAttempt();
			$this->deleteRequest($data['id']);
			return array(FALSE,$this->mod->Lang('system_error').' #02');
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET isactive=1 WHERE id=?';
		$this->db->Execute($sql,array($data['uid']));

		$this->deleteRequest($data['id']);

		return array(TRUE,$this->mod->Lang('account_activated'));
	}

	/**
	* Creates a reset-key for a login and sends email
	* @login string user identifier
	* @sendmail boolean whether to send confirmation email default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function requestReset($login, $sendmail=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->validateLogin($login);

		if (!$status[0]) {
	//TODO minimise impact of $login brute-forcing
			return array(FALSE,$this->mod->Lang('login_invalid'));
		}

		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE login=?';
		$id = $this->db->GetOne($sql,array($login));

		if (!$id) {
	//TODO minimise impact of $login brute-forcing
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('login_incorrect'));
		}

		$status = $this->addRequest($id,$login,'reset',$sendmail);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		$msg = ($sendmail) ?
		 $this->mod->Lang('reset_requested') :
		 $this->mod->Lang('reset_requested_loginmessage_suppressed');
		return array(TRUE,$msg);
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
	* Get specified property(ies) for @context
	* @context string login-context-alias or int login-context-identifier or NULL
	* @propkey string property-name or array of them (not validated here)
	* Returns: property value or assoc. array of them
	*/
	private function getConfig($context, $propkey)
	{
		if ($context) {
			if (is_array($propkey)) {
				$sql2 = implode(',',$propkey);
			} else {
				$sql2 = $propkey;
			}
			if (is_int($context)) {
				$sql3 = 'id';
			} else {
				$sql3 = 'alias';
			}

			$sql = 'SELECT '.$sql2.' FROM '.$this->pref.'module_auth_contexts WHERE '.$sql3.'=?';
			$data = $this->db->GetRow($sql,array($context));
			if ($data) {
				//grab defaults for 'empty' settings
				foreach ($data as $key=>&$val) {
					if (0) { //TODO empty test
						$val = $this->mod->GetPreference($key,NULL);
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
			$data = array();
			foreach ($propkey as $key) {
				$data[$key] = $this->mod->GetPreference($key,NULL);
			}
			return $data;
		} else {
			return $this->mod->GetPreference($propkey,NULL);
		}
	}

	/**
	* Hashes the provided password using Bcrypt
	* @password plaintext string
	* Returns: hashed password string
	*/
	public function getHash($password)
	{
		$val = $this->getConfig($this->context,'bcrypt_cost');
		return password_hash($password,PASSWORD_BCRYPT,array('cost'=>$val));
	}

	/**
	* Gets user-enumerator for the given login
	* @login string user identifier
	* Returns: user enumerator
	*/
	public function getUID($login)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE login=?';
		return $this->db->GetOne($sql,array($login));
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

		$val = $this->getConfig($this->context,'session_key');
		$hash = sha1(uniqid($val,TRUE));

		$data = array('hash'=>$hash,'cookie_hash'=>sha1($hash.$val);

		$dt = new \DateTime('@'.time(),NULL);
		if ($remember) {
			$val = $this->getConfig($this->context,'cookie_remember');
			$dt->modify('+'.$val);
			$data['expire'] = $dt->getTimestamp();
			$data['expiretime'] = $data['expire'];
		} else {
			$val = $this->getConfig($this->context,'cookie_forget');
			$dt->modify('+'.$val);
			$data['expire'] = $dt->getTimestamp();
			$data['expiretime'] = 0;
		}

		$ip = $this->getIp();
		$agent = $_SERVER['HTTP_USER_AGENT'];

		$sql = 'INSERT INTO '.$this->pref.'module_auth_sessions (uid,hash,expire,ip,agent,cookie_hash) VALUES (?,?,?,?,?,?)';

		if (!$this->db->Execute($sql,array($uid,$hash,$data['expire'],$ip,$agent,$data['cookie_hash']))) {
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
		$res = $this->db->Execute($sql,array($uid));
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
		$res = $this->db->Execute($sql,array($hash));
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
		$row = $this->db->GetRow($sql,array($hash));

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

		$val = $this->getConfig($this->context,'session_key');
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
		return $this->db->GetOne($sql,array($hash));
	}

	/**
	* Checks if a login name is already in use
	* @login string user identifier
	* Returns: boolean
	*/
	public function isLoginTaken($login)
	{
		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE login=? AND context=?';
		$num = $this->db->GetOne($sql,array($login,$this->context));
		return ($num > 0);
	}

	/**
	* Records a new user
	* @login string user identifier
	* @password plaintext string
	* @email email address for messages, possibly empty
	* @sendmail  reference to boolean whether to send confirmation email messages
	* @params array of additional params default = empty
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function addUser($login, $password, $email, &$sendmail, $params=array())
	{
		$uid = $this->db->GenID($this->pref.'module_auth_users_seq');
		$login = htmlentities($login); //TODO encoding management

		if ($sendmail) { //TODO
			$status = $this->addRequest($uid,$login,'activate',$sendmail);

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

		$sql = 'INSERT INTO '.$this->pref.'module_auth_users (id,login,passhash,email,isactive) VALUES (?,?,?,?,?)';

		if (!$this->db->Execute($sql,array($uid,$login,$password,$email,$isactive))) {
			$this->deleteRequest($status[$TODO]);
			return array(FALSE,$this->mod->Lang('system_error').' #03');
		}

		if (is_array($params) && count($params) > 0) { //TODO
		}

		return array (TRUE,'');
	}

	/**
	* Gets basic user-data for the given UID
	* @uid int user enumerator
	* Returns: array with members 'uid','login','password','isactive', or else FALSE
	*/
	protected function getBaseUser($uid)
	{
		$sql = 'SELECT login,passhash,isactive FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql,array($uid));

		if ($data) {
			$data['uid'] = $uid;
			return $data;
		}
		return FALSE;
	}

	/**
	* Gets all user-data except password,factor2 for the given UID
	* @ int $uid user enumerator
	* Returns: array with members 'uid','email','login','isactive', or else FALSE
	*/
	public function getUser($uid)
	{
		$sql = 'SELECT * FROM '.$this->pref.'module_auth_users WHERE id=?';
		$data = $this->db->GetRow($sql,array($uid));

		if ($data) {
			unset($data['id']);
			unset($data['password']);
			$data['uid'] = $uid; //=data['id']
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
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->matchPassword($uid,$password);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang(TODO));
		}

		if (!password_verify($password,$userdata['password'])) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('password_incorrect'));
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_users WHERE id=?';

		if (!$this->db->Execute($sql,array($uid))) {
			return array(FALSE,$this->mod->Lang('system_error').' #05');
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE uid=?';

		if (!$this->db->Execute($sql,array($uid))) {
			return array(FALSE,$this->mod->Lang('system_error').' #06');
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_requests WHERE uid=?';

		if (!$this->db->Execute($sql,array($uid))) {
			return array(FALSE,$this->mod->Lang('system_error').' #07');
		}

		$this->mod->SendEvent('OnDeregister',$parms);

		return array(TRUE,$this->mod->Lang('account_deleted'));
	}

/*		if ($this->mailer === NULL) {
			if($this->mod->before20) {
				$this->mailer = \cms_utils::get_module('CMSMailer');
				$this->loaded = FALSE;
				if(!$this->mailer) {
					TODO prevent messaging
				}
			} else {
				$this->mailer = new \cms_mailer();
				$this->loaded = TRUE;
			}
		}

	/**
	DoSend:
	Sends email(s)
	@mod: reference to current module object
	@subject: email subject
	@to: array of destinations, or FALSE (in which case @cc will be substituted if possible).
		Array key = recipient name or ignored number, value = validated email address
	@cc: array of 'CC' destinations, or FALSE. Array format as for @to
	@bcc: array of 'BCC' destinations, or FALSE. Array format as for @to
	@from: 1-member array, or FALSE to use default
		Array key = sender name or ignored number, value = validated email address
	@body: the message
	@html: optional boolean - whether to format message as html default FALSE
	Returns: 2-member array -
	 [0] FALSE if no destination or no mailer module, otherwise boolean result of mailer->Send()
	 [1] '' or error message e.g. from mailer->Send()
	* /
	protected function DoSend(&$mod,$subject,$to,$cc,$bcc,$from,$body,$html=FALSE)
	{
		if(!($to || $cc))
			return array(FALSE,'');
		if(!$this->mailer)
			return array(FALSE,$mod->Lang('err_system'));
		if(!$this->loaded)
		{
			$this->mailer->_load();
			$this->loaded = TRUE;
		}
		//TODO	conform message encoding to $mailer->CharSet
		$m = $this->mailer;
		$m->reset();
		if($to)
		{
			foreach($to as $name=>$address)
			{
				if(is_numeric($name))
					$name = '';
				$m->AddAddress($address,$name);
			}
			if($cc)
			{
				foreach($cc as $name=>$address)
				{
					if(is_numeric($name))
						$name = '';
					$m->AddCC($address,$name);
				}
			}
		}
		elseif($cc)
		{
			foreach($cc as $name=>$address)
			{
				if(is_numeric($name))
					$name = '';
				$m->AddAddress($address,$name);
			}
		}
		if($bcc)
		{
			foreach($bcc as $name=>$address)
			{
				if(is_numeric($name))
					$name = '';
				$m->AddBCC($address,$name);
			}
		}
		if($from) //default sender isn't wanted
		{
			$name = key($from);
			if(is_numeric($name))
				$name = '';
			$m->SetFrom(reset($from),$name);
		}
		$m->SetSubject($subject);
		$m->IsHTML($html);
		if($html)
		{
			$m->SetBody($body);
			//PHP is bad at setting suitable line-breaks
			$tbody = str_replace(
				array('<br /><br />','<br />','<br><br>','<br>'),
				array('','','',''),$body);
			$tbody = strip_tags(html_entity_decode($tbody));
			$m->SetAltBody($tbody);
		}
		else
		{
			$m->SetBody(html_entity_decode($body));
		}
		$res = $m->Send();
		$err = ($res) ? '' : $m->GetErrorInfo();
		$m->reset();
		return array($res,$err);
	}
*/

	/**
	* Creates an activation entry and sends login to user
	* @uid int user enumerator
	* @login string user identifier
	* @type string 'reset' or 'activate'
	* @sendmail boolean reference whether to send confirmation email
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function addRequest($uid, $login, $type, &$sendmail)
	{
		if (!($type == 'activate' || $type == 'reset')) {
			return array(FALSE,$this->mod->Lang('system_error').' #08');
		}

		// if not set manually, check config data
		if ($sendmail === NULL) {
			$sendmail = TRUE;
			if ($type == 'reset') {
				$val = $this->getConfig($this->context,'suppress_reset_message');
				if ($val) {
					$sendmail = FALSE;
					return array(TRUE,'');
				}
			} elseif ($type == 'activate') {
				$val = $this->getConfig($this->context,'suppress_activation_message');
				if ($val) {
					$sendmail = FALSE;
					return array(TRUE,'');
				}
			}
		}

		$sql = 'SELECT id,expire FROM '.$this->pref.'module_auth_requests WHERE uid=? AND type=?';
		$row = $this->db->GetRow($sql,array($uid,$type));

		if ($row) {
			if ($row['expire'] > time()) {
				return array(FALSE,$this->mod->Lang('reset_exists'));
			}
			$this->deleteRequest($row['id']);
		}

		if ($type == 'activate') {
			$userdata = $this->getBaseUser($uid);
			if ($userdata['isactive']) {
				return array(FALSE,$this->mod->Lang('already_activated'));
			}
		}

		$dt = new \DateTime('@'.time(),NULL);
		$val = $this->getConfig($this->context,'request_key_expiration');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$val = $this->getRandomKey(self::KEYSALT);
		$key = uniqid($val,FALSE);

		$request_id = $this->db->GenID($this->pref.'module_auth_requests_seq');

		$sql = 'INSERT INTO '.$this->pref.'module_auth_requests (id,uid,expire,rkey,type) VALUES (?,?,?,?,?)';

		if (!$this->db->Execute($sql,array($request_id,$uid,$expiretime,$key,$type))) {
			return array(FALSE,$this->mod->Lang('system_error').' #09');
		}

		if ($sendmail === TRUE) {
			//TODO CMSMailer module
			// Check configuration for SMTP parameters
			$mail = new PHPMailer;
			$mail->CharSet = $this->config->mail_charset;
			if ($this->config->smtp) {
				$mail->isSMTP();
				$mail->Host = $this->config->smtp_host;
				$mail->SMTPAuth = $this->config->smtp_auth;
				if (!is_null($this->config->smtp_auth)) {
					$mail->Username = $this->config->smtp_username;
					$mail->Password = $this->config->smtp_password;
				}
				$mail->Port = $this->config->smtp_port;

				if (!is_null($this->config->smtp_security)) {
					$mail->SMTPSecure = $this->config->smtp_security;
				}
			}

			$mail->From = $this->config->site_login;
			$mail->FromName = $this->config->site_name;
			$mail->addAddress($login);
			$mail->isHTML(TRUE);

			if ($type == 'activate') {
					$mail->Subject = sprintf($this->mod->Lang('login_activation_subject'), $this->config->site_name);
					$mail->Body = sprintf($this->mod->Lang('login_activation_body'), $this->config->site_url, $this->config->site_activation_page, $key);
					$mail->AltBody = sprintf($this->mod->Lang('login_activation_altbody'), $this->config->site_url, $this->config->site_activation_page, $key);
			} else {
				$mail->Subject = sprintf($this->mod->Lang('login_reset_subject'), $this->config->site_name);
				$mail->Body = sprintf($this->mod->Lang('login_reset_body'), $this->config->site_url, $this->config->site_password_reset_page, $key);
				$mail->AltBody = sprintf($this->mod->Lang('login_reset_altbody'), $this->config->site_url, $this->config->site_password_reset_page, $key);
			}

			if (!$mail->send()) {
				$this->deleteRequest($request_id);
				return array(FALSE,$this->mod->Lang('system_error').' #10');
			}
		}

		return array(TRUE,'');
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
		$row = $this->db->GetRow($sql,array($key,$type));

		if (!$row) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang($type.'key_incorrect'));
		}

		if ($row['expire'] < time()) {
			$this->addAttempt();
			$this->deleteRequest($row['id']);
			return array(FALSE,$this->mod->Lang($type.'key_expired'));
		}

		return array(0=>TRUE,1=>'','id'=>$row['id'],'uid'=>$row['uid']);
	}

	/**
	* Deletes request from database
	* @id int request enumerator
	* Returns: boolean
	*/
	protected function deleteRequest($id)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_requests WHERE id=?';
		$res = $this->db->Execute($sql,array($id));
		return ($res != FALSE);
	}

	/**
	* Verifies that @login is a valid login indentifier
	* @login string user identifier
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function validateLogin($login)
	{
		$val = (int)$this->getConfig($this->context,'login_min_length');
		if ($val > 0 && strlen($login) < $val) {
			return array(FALSE,$this->mod->Lang('login_short'));
		}

		$val = (int)$this->getConfig($this->context,'login_max_length');
		if ($val > 0 && strlen($login) > $val) {
			return array(FALSE,$this->mod->Lang('login_long'));
		}

		if (preg_match(self::EMAILPATN,$login)) {
			$val = $this->getConfig($this->context,'login_use_banlist');
			if ($val) {
				$parts = explode('@',$login);
				$bannedDomains = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
				if (in_array(strtolower($parts[1]),$bannedDomain)) {
					return array(FALSE,$this->mod->Lang('email_banned'));
				}
			}
		}

		return array(TRUE,'');
	}

	/**
	* Verifies that @email is an acceptable email address
	* @email string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function validateEmail($email)
	{
		if (!$email || !preg_match(self::EMAILPATN,$email)) {
			return array(FALSE,$this->mod->Lang('email_invalid'));
		}

		$parts = explode('@',$email);
		$bannedDomains = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
		if (in_array(strtolower($parts[1]),$bannedDomains)) {
			return array(FALSE,$this->mod->Lang('email_banned'));
		}
		return array(TRUE,'');
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
			return array(FALSE,$this->mod->Lang('system_error').' #11');
		}

		if (!password_verify($password,$userdata['password'])) {
			return array(FALSE,$this->mod->Lang('password_notvalid'));
		}
		return array(TRUE,'');
	}

	/**
	* Verifies that @password respects security requirements
	* @password plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function validatePassword($password)
	{
		$val = (int)$this->getConfig($this->context,'password_min_length');
		if ($val > 0 && strlen($password) < $val) {
			return array(FALSE,$this->mod->Lang('password_short'));
		}

		require __DIR__.DIRECTORY_SEPARATOR.zxcvbn.DIRECTORY_SEPARATOR.Zxcvbn.php;
		$zxcvbn = new ZxcvbnPhp\Zxcvbn();
		$check = $zxcvbn->passwordStrength($password);

		$val = (int)$this->getConfig($this->context,'password_min_score');
		if ($check['score'] < $val) {
			return array(FALSE,$this->mod->Lang('password_weak'));
		}

		return array(TRUE,'');
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
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		if (strlen($key) != 32) {
			return array(FALSE,$this->mod->Lang('resetkey_invalid'));
		}

		$data = $this->getRequest($key,'reset');

		if (!$data[0]) {
			return $data;
		}

		$status = $this->matchPassword($data['uid'],$password);

		if (!$status[0]) {
			return $status;
		}

		if ($password !== $repeatpassword) {
			// Passwords don't match
			return array(FALSE,$this->mod->Lang('newpassword_nomatch'));
		}

		$userdata = $this->getBaseUser($data['uid']);

		if (!$userdata) {
			$this->addAttempt();
			$this->deleteRequest($data['id']);
			return array(FALSE,$this->mod->Lang('system_error').' #11');
		}

		if (password_verify($password,$userdata['password'])) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('newpassword_match'));
		}

		$password = $this->getHash($password);
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
		$res = $this->db->Execute($sql,array($password,$data['uid']));

		if ($res) {
			$this->deleteRequest($data['id']);
			return array(TRUE,$this->mod->Lang('password_reset'));
		}
		return array(FALSE,$this->mod->Lang('system_error').' #12');
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
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->matchPassword($uid,$currpass);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		$status = $this->validatePassword($newpass);

		if (!$status[0]) {
			return $status;
		} elseif ($newpass !== $repeatnewpass) {
			return array(FALSE,$this->mod->Lang('newpassword_nomatch'));
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('system_error').' #13');
		}

		if (!password_verify($currpass,$userdata['password'])) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('password_incorrect'));
		}

		$newpass = $this->getHash($newpass);

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
		$this->db->Execute($sql,array($newpass,$uid));
		return array(TRUE,$this->mod->Lang('password_changed'));
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
		$password = $this->db->GetOne($sql,array($uid));

		if ($password) {
			return password_verify($password_for_check,$password);
		}
		return FALSE;
	}

	/**
	* Changes a user's login name
	* @uid int user enumerator
	* @login string user identifier
	* @password plaintext string
	* Returns: array 0=>T/F, 1=>message
	*/
	public function changelogin($uid, $login, $password)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if (0) { //TODO
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->validateLogin($login);

		if (!$status[0]) {
			return $status;
		}

		$status = $this->matchPassword($uid,$password);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('system_error').' #14');
		}

		if (!password_verify($password,$userdata['password'])) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('password_incorrect'));
		}

		if ($login == $userdata['login']) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('newlogin_match'));
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET login=? WHERE id=?';
		$res = $this->db->Execute($sql,array($login,$uid));

		if ($res == FALSE) {
			return array(FALSE,$this->mod->Lang('system_error').' #15');
		}

		return array(TRUE,$this->mod->Lang('login_changed'));
	}

	/**
	* Recreates activation email for @login and sends that email
	* @login string user identifier
	* @sendmail default = NULL  whether to send email notice
	* Returns: array 0=>T/F, 1=>message
	*/
	public function resendActivation($login, $sendmail=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		if ($sendmail == NULL) {
			return array(FALSE,$this->mod->Lang('function_disabled'));
		}

		$status = $this->validateLogin($login);

		if (!$status[0]) {
			return $status;
		}

		$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE login=?';
		$id = $this->db->GetOne($sql,array($login));

		if ($id == FALSE) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('login_incorrect'));
		}

		$userdata = $this->getBaseUser($id);

		if ($userdata['isactive']) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('already_activated'));
		}

		$status = $this->addRequest($id,$login,'activate',$sendmail);

		if (!$status[0]) {
			$this->addAttempt();
			return $status;
		}

		return array(TRUE,$this->mod->Lang('activation_sent'));
	}

	/**
	* Reports access-status for the current ip address
	* Returns: string 'allow','verify' or 'block'
	*/
	public function isBlocked()
	{
		$ip = $this->getIp();
		$this->deleteAttempts($ip,FALSE);
		$sql = 'SELECT count(*) FROM '.$this->pref.'module_auth_attempts WHERE ip=?';
		$attempts = $this->db->GetOne($sql,array($ip));

		$val = (int)$this->getConfig($this->context,'attempts_before_verify');
		if ($val > 0 && $attempts < $val) {
			return 'allow';
		}

		$val = (int)$this->getConfig($this->context,'attempts_before_ban');
		if ($val > 0 && $attempts < $val) {
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
		$dt = new \DateTime('@'.time(),NULL);
		$val = $this->getConfig($this->context,'attack_mitigation_time');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$sql = 'INSERT INTO '.$this->pref.'module_auth_attempts (ip,expire) VALUES (?,?)';
		$res = $this->db->Execute($sql,array($ip,$expiretime));
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
			$res = $this->db->Execute($sql,array($ip));
		} else {
			$sql = 'DELETE FROM '.$this->pref.'module_auth_attempts WHERE ip=? AND expire<?';
			$nowtime = time();
			$res = $this->db->Execute($sql,array($ip,$nowtime));
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
		$chars = 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6';
		$cl = strlen($chars) - 1;
		$key = '';

		for ($i = 0; $i < $length; $i++) {
			$key .= $chars{mt_rand(0,$cl)};
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
		$val = $this->getConfig($this->context,'cookie_name');
		return (isset($_COOKIE[$val]) && $this->checkSession($_COOKIE[$val]));
	}

	/**
	* Gets current session hash
	* Returns: string
	*/
	public function getSessionHash()
	{
		$val = $this->getConfig($this->context,'cookie_name');
		return $_COOKIE[$val];
	}
}
