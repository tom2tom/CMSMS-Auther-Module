<?php
/**
Auth class
Apapted for CMSMS from PHP Auth <https://www.phpclasses.org/package/9887-PHP-Register-and-login-users-stored-in-a-database.html>

Requires PHP 5.3+
*/
namespace CMSAuth;

class Auth
{
	define KEYSALT 19; //prefix-length 19 + 13 from uniqid() = 32

	protected $mod;
	protected $pref;
	protected $db;
	protected $context;
	protected $mlr;
	
/*
		global $CMS_VERSION;
		if(version_compare($CMS_VERSION,'2.0') < 0)
		{
			$this->mlr = \cms_utils::get_module('CMSMailer');
			if($this->mlr)
				$this->loaded = FALSE;
			else
				throw new NoHelperException();
		}
		else
		{
			$this->mlr = new cms_mailer();
			$this->loaded = TRUE;
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
	 [0] FALSE if no destination or no mailer module, otherwise boolean result of mlr->Send()
	 [1] '' or error message e.g. from mlr->Send()
	* /
	protected function DoSend(&$mod,$subject,$to,$cc,$bcc,$from,$body,$html=FALSE)
	{
		if(!($to || $cc))
			return array(FALSE,'');
		if(!$this->mlr)
			return array(FALSE,$mod->Lang('err_system'));
		if(!$this->loaded)
		{
			$this->mlr->_load();
			$this->loaded = TRUE;
		}
		//TODO	conform message encoding to $mlr->CharSet
		$m = $this->mlr;
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

	public function __construct(&$mod, $context)
	{
		$this->mod = $mod;
		$this->db = \cmsms()->GetDb();
		$tnis->pref = \cms_db_prefix();
		$this->context = $context;

		if (\version_compare(\phpversion(),'5.5.0','<')) {
			require(__DIR__.'password.php');
		}
//		$config = cmsms()->GetConfig();
//		$val = $this->getConfig($this->context,'site_timezone'];
//		date_default_timezone_set($val); TODO
	}

	/**
	* Logs a user in
	* @login string user identifier
	* @password plaintext string
	* @remember int default = 0
	* @captcha string default = NULL
	* Returns: array, 0=>T/F for success, 1=>message, if success then also 'hash','expire'
	*/
	public function login($login, $password, $remember=0, $captcha=NULL) //TODO FACTOR
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if ($this->checkCaptcha($captcha) == FALSE) { //TODO FACTOR
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->validateLogin($login);
		if (!$status[0]) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('login_notvalid'));
		}

		$status = $this->validatePassword($password);
		if (!$status[0]) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('password_notvalid'));
		}

		if ($remember != 0 && $remember != 1) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('remember_me_invalid'));
		}

		$uid = $this->getUID(strtolower($login));

		if (!$uid) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('login_incorrect'));
		}

		$userdata = $this->getBaseUser($uid);

		if (!password_verify($password,$userdata['password'])) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('authority_failed'));
		}

		if (!$userdata['isactive']) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('account_inactive'));
		}

		$sessiondata = $this->addSession($userdata['uid'],$remember);

		if (!$sessiondata) {
			return array(FALSE,$this->mod->Lang('system_error').' #01');
		}

		$data = array(TRUE,$this->mod->Lang('logged_in'));
		$data['hash'] = $sessiondata['hash'];
		$data['expire'] = $sessiondata['expiretime'];
		return $data;
	}

	/**
	* Creates a new user, adds her/him to database
	* @login string user identifier
	* @password plaintext string
	* @repeatpassword plaintext string
	* @email email address for notices
	* @params array parameters for self::addUser() default = empty
	* @captcha string default = NULL
	* @sendmail bool whether to send confirmation email default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function register($login, $password, $repeatpassword, $email, $params=array(), $captcha=NULL, $sendmail=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if ($this->checkCaptcha($captcha) == FALSE) {
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		if ($password !== $repeatpassword) {
			return array(FALSE,$this->mod->Lang('password_nomatch'));
		}

		// Validate login
		$status = $this->validateLogin($login);

		if (!$status[0]) {
			return $status;
		}

		// Validate password
		$status = $this->validatePassword($password);

		if (!$status[0]) {
			return $status;
		}

		require __DIR__.DIRECTORY_SEPARATOR.zxcvbn.DIRECTORY_SEPARATOR.Zxcvbn.php;
		$zxcvbn = new ZxcvbnPhp\Zxcvbn();
		$check = $zxcvbn->passwordStrength($password);

		$val = (int)$this->getConfig($this->context,'password_min_score');
		if ($check['score'] < $val) {
			return array(FALSE,$this->mod->Lang('password_weak'));
		}

		if ($this->isLoginTaken($login)) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('login_taken'));
		}

		$status = $this->addUser($login,$password,$params,$sendmail);

		if (!$status[0]) {
			return $status;
		}

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
		$this->db->execute($sql,array($data['uid']));

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
	* Get value(s) of specified property(ies) for specified context
	* @context string or int login-context identifier
	* @propkey string field-name or array of them (not checked here)
	* Returns: propety value or array of them
	*/
	private function getConfig($context,$propkey)
	{
		if (is_array($propkey) {
			$sql2 = implode(',',$propkey); 
		} else {
			$sql2 = $propkey;
		}
		if (is_int($context) {
			$sql3 = 'id';
		} else {
			$sql3 = 'alias';
		}

		$sql = 'SELECT '.$sql2.' FROM '.$this->pref.'module_auth_contexts WHERE '.$sql3.'=?';
		$data = $this->db->GetRow($sql,array($context));
		if ($data) {
			//TODO grab defaults for 'empty' settings
			if ($sql2 == $propkey) {
				return $data[$propkey];
			} else {
				return $data;
			}
		} else {
			//TODO grab defaults
			return FALSE;
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
		return password_hash($password, PASSWORD_BCRYPT, array('cost'=>$val));
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
	* Creates a session for a specified user id
	* @uid int user enumerator
	* @remember boolean whether to log an expiry time for the session
	* Returns: array with members 'hash','expire','expiretime','cookie_crc' or else FALSE
	*/
	protected function addSession($uid, $remember)
	{
		$userdata = $this->getBaseUser($uid);
		if (!$userdata) {
			return FALSE;
		}

		$ip = $this->getIp();
		$val = $this->getConfig($this->context,'site_key');

		$data = array('hash' => sha1($val.microtime()));
		$data['cookie_crc'] = sha1($data['hash'].$val);
		$agent = $_SERVER['HTTP_USER_AGENT'];

		$this->deleteExistingSessions($uid);

		if ($remember) {
			$val = $this->getConfig($this->context,'cookie_remember');
			$data['expire'] = date('Y-m-d H:i:s', strtotime($val));
			$data['expiretime'] = strtotime($data['expire']);
		} else {
			$val = $this->getConfig($this->context,'cookie_forget');
			$data['expire'] = date('Y-m-d H:i:s', strtotime($val));
			$data['expiretime'] = 0;
		}

		$sql = 'INSERT INTO '.$this->pref.'module_auth_sessions (uid,hash,expire,ip,agent,cookie_crc) VALUES (?,?,?,?,?,?)';

		if (!$this->db->execute($sql,array($uid,$data['hash'],$data['expire'],$ip,$agent,$data['cookie_crc']))) {
			return FALSE;
		}

		$data['expire'] = strtotime($data['expire']);

		return $data;
	}

	/**
	* Removes all existing sessions for a given UID
	* @uid int user enumerator
	* Returns: boolean
	*/
	protected function deleteExistingSessions($uid)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE uid=?';
		$res = $this->db->execute($sql,array($uid));
		return ($res != FALSE);
	}

	/**
	* Removes a session based on hash
	* @hash string
	* Returns: boolean
	*/
	protected function deleteSession($hash)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE hash=?';
		$res = $this->db->execute($sql, array($hash));
		return ($res != FALSE);
	}

	/**
	* Function to check if a session is valid
	* @hash string
	* Returns: boolean
	*/
	public function checkSession($hash)
	{
		$ip = $this->getIp();
		$block_status = $this->isBlocked();

		if ($block_status == 'block') {
			return FALSE;
		}

		if (strlen($hash) != 40) {
			return FALSE;
		}

		$sql = 'SELECT id,uid,expire,ip,agent,cookie_crc FROM '.$this->pref.'module_auth_sessions WHERE hash=?';
		$row = $this->db->GetRow($sql,array($hash));

		if (!$row) {
			return FALSE;
		}

		$sid = $row['id'];
		$uid = $row['uid'];
		$expiretime = strtotime($row['expire']);
		$nowtime = strtotime(date('Y-m-d H:i:s'));
		$db_ip = $row['ip'];
		$db_agent = $row['agent'];
		$db_cookie = $row['cookie_crc'];

		if ($nowtime > $expiretime) {
			$this->deleteExistingSessions($uid);
			return FALSE;
		}

		if ($ip != $db_ip) {
			return FALSE;
		}

		$val = $this->getConfig($this->context,'site_key');
		if ($db_cookie == sha1($hash.$val)) {
			return TRUE;
		}

		return FALSE;
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
		$sql = 'SELECT count(*) FROM '.$this->pref.'module_auth_users WHERE login=?';
		$num = $this->db->GetOne($sql,array($login));
		return ($num > 0);
	}

	/**
	* Adds a new user to database
	* @login string user identifier
	* @password plaintext string
	* @params array -- additional params
	* @sendmail  -- reference to boolean  whether to send confirmation email
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function addUser($login, $password, $params=array(), &$sendmail)
	{
		$sql = 'INSERT INTO '.$this->pref.'module_auth_users VALUES ()';
		if (!$this->db->execute($sql)) {
			return array(FALSE,$this->mod->Lang('system_error').' #03');
		}

		$uid = $this->db->lastInsertId();
		$login = htmlentities(strtolower($login));

		if ($sendmail) { //TODO
			$status = $this->addRequest($uid,$login,'activate',$sendmail);

			if (!$status[0]) {
				$sql = 'DELETE FROM '.$this->pref.'module_auth_users WHERE id=?';
				$this->db->execute($sql,array($uid));
				return $status;
			}

			$isactive = 0;
		} else {
			$isactive = 1;
		}

		$password = $this->getHash($password);

		if (is_array($params)&& count($params) > 0) {
			$customParamsQueryarray = array();

			foreach($params as $paramKey => $paramValue) {
				$customParamsQueryarray[] = array('value' => $paramKey . ' = ?');
			}

			$setParams = ', ' . implode(', ', array_map(function ($entry) {
				return $entry['value'];
			}, $customParamsQueryarray));
		} else { $setParams = ''; }

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET login=?,passhash=?,isactive=? '.$setParams.' WHERE id=?';

		$bindParams = array_values(array_merge(array($login, $password, $isactive), $params, array($uid)));

		if (!$this->db->execute($sql,$bindParams)) {
			$sql = 'DELETE FROM '.$this->pref.'module_auth_users WHERE id=?';
			$this->db->execute($sql, array($uid));
			return array(FALSE,$this->mod->Lang('system_error').' #04');
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
			unset($data['factor2']);
			$data['uid'] = $uid; //=data['id']
			return $data;
		}
		return FALSE;
	}

	/**
	* Allows a user to delete their account
	* @uid int user enumerator
	* @password string plaintext
	* @captcha string default = NULL
	* Returns: array 0=>T/F for success, 1=>message
	*/
	public function deleteUser($uid, $password, $captcha=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if ($this->checkCaptcha($captcha) == FALSE) {
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->validatePassword($password);

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

		if (!$this->db->execute($sql,array($uid))) {
			return array(FALSE,$this->mod->Lang('system_error').' #05');
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE uid=?';

		if (!$this->db->execute($sql,array($uid))) {
			return array(FALSE,$this->mod->Lang('system_error').' #06');
		}

		$sql = 'DELETE FROM '.$this->pref.'module_auth_requests WHERE uid=?';

		if (!$this->db->execute($sql,array($uid))) {
			return array(FALSE,$this->mod->Lang('system_error').' #07');
		}

		return array(TRUE,$this->mod->Lang('account_deleted'));
	}

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
		$row = $this->db->GetRow($sql, array($uid, $type));

		if ($row) {
			$expiretime = strtotime($row['expire']);
			$nowtime = strtotime(date('Y-m-d H:i:s'));

			if ($nowtime < $expiretime) {
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

		$val = $this->getRandomKey(self::KEYSALT);
		$key = uniqid($val,FALSE);

		$val = $this->getConfig($this->context,'request_key_expiration');
		$expiretime = date('Y-m-d H:i:s', strtotime($val));

		$sql = 'INSERT INTO '.$this->pref.'module_auth_requests (uid,rkey,expire,type) VALUES (?,?,?,?)';

		if (!$this->db->execute($sql, array($uid, $key, $expiretime, $type))) {
			return array(FALSE,$this->mod->Lang('system_error').' #09');
		}

		$request_id = $this->db->lastInsertId();

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
	* Returns request data if key is valid
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
			return array(FALSE,$this->mod->Lang($type.'key_incorrect')); //TODO
		}

		$expire = strtotime($row['expire']); //TODO timezone
		$nowtime = strtotime(date('Y-m-d H:i:s'));

		if ($nowtime > $expire) {
			$this->addAttempt();
			$this->deleteRequest($row['id']);
			return array(FALSE,$this->mod->Lang($type.'key_expired')); //TODO
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
		$res = $this->db->execute($sql,array($id));
		return ($res != FALSE);
	}

	/**
	* Verifies that login name is valid
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

/* TODO if login is email
		$val = (int)$this->getConfig($this->context,'login_use_banlist');
		if ($val) {
			$bannedEmails = json_decode(file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'domains.json'));
			$parts = explode('@',$login);
			if (in_array(strtolower($parts[1]),$bannedEmails)) {
				return array(FALSE,$this->mod->Lang('email_banned'));
			}
		}
*/
		return array(TRUE,'');
	}

	/**
	* Verifies that supplied email addesss is valid
	* @email string 
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function validateEmail($email)
	{
	}

	/**
	* Verifies that suppied password is valid and respects security requirements
	* @password plaintext string
	* Returns: array 0=>T/F for success, 1=>message
	*/
	protected function validatePassword($password)
	{
		$val = (int)$this->getConfig($this->context,'password_min_length');
		if ($val > 0 && strlen($password) < $val) {
			return array(FALSE,$this->mod->Lang('password_short'));
		}
		return array(TRUE,'');
	}

	/**
	* Allows a user to reset her/his password after requesting a reset key.
	* @key string 
	* @password string $
	* @repeatpassword string $
	* @captcha string default = NULL
	* Returns: array $ret
	*/
	public function resetPassword($key, $password, $repeatpassword, $captcha=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if ($this->checkCaptcha($captcha) == FALSE) {
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		if (strlen($key) != 20) {
			return array(FALSE,$this->mod->Lang('resetkey_invalid'));
		}

		$status = $this->validatePassword($password);

		if (!$status[0]) {
			return $status;
		}

		if ($password !== $repeatpassword) {
			// Passwords don't match
			return array(FALSE,$this->mod->Lang('newpassword_nomatch'));
		}

		$data = $this->getRequest($key,'reset');

		if (!$data[0]) {
			return $data;
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
		$res = $this->db->execute($sql,array($password,$data['uid']));

		if ($res) {
			$this->deleteRequest($data['id']);
			return array(TRUE,$this->mod->Lang('password_reset'));
		}
		return array(FALSE,$this->mod->Lang('system_error').' #12');
	}

	/**
	* Recreates activation email for a given email and sends
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
	* Changes a user's password
	* @uid int user enumerator
	* @currpass plaintext string
	* @newpass plaintext string
	* @repeatnewpass plaintext string
	* @captcha string default = NULL
	* Returns: array 0->T/F, 1=>message
	*/
	public function changePassword($uid, $currpass, $newpass, $repeatnewpass, $captcha=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') { //TODO FACTOR
			if ($this->checkCaptcha($captcha) == FALSE) {
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->validatePassword($currpass);

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

		require __DIR__.DIRECTORY_SEPARATOR.zxcvbn.DIRECTORY_SEPARATOR.Zxcvbn.php;
		$zxcvbn = new ZxcvbnPhp\Zxcvbn();
		$check = $zxcvbn->passwordStrength($newpass);

		$val = (int)$this->getConfig($this->context,'password_min_score');

		if ($check['score'] < $val) {
			return array(FALSE,$this->mod->Lang('password_weak'));
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('system_error').' #13');
		}

		if (!password_verify($currpass, $userdata['password'])) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('password_incorrect'));
		}

		$newpass = $this->getHash($newpass);

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET passhash=? WHERE id=?';
		$this->db->execute($sql,array($newpass,$uid));
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
	* @captcha string default = NULL
	* Returns: array 0=>T/F, 1=>message
	*/
	public function changelogin($uid, $login, $password, $captcha=NULL)
	{
		$block_status = $this->isBlocked();

		if ($block_status == 'verify') {
			if ($this->checkCaptcha($captcha) == FALSE) {
				return array(FALSE,$this->mod->Lang('user_verify_failed'));
			}
		} elseif ($block_status == 'block') {
			return array(FALSE,$this->mod->Lang('user_blocked'));
		}

		$status = $this->validateLogin($login);

		if (!$status[0]) {
			return $status;
		}

		$status = $this->validatePassword($password);

		if (!$status[0]) {
			return array(FALSE,$this->mod->Lang('password_notvalid'));
		}

		$userdata = $this->getBaseUser($uid);

		if (!$userdata) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('system_error').' #14');
		}

		if (!password_verify($password, $userdata['password'])) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('password_incorrect'));
		}

		if ($login == $userdata['login']) {
			$this->addAttempt();
			return array(FALSE,$this->mod->Lang('newlogin_match'));
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET login=? WHERE id=?';
		$res = $this->db->execute($sql,array($login,$uid));

		if ($res == FALSE) {
			return array(FALSE,$this->mod->Lang('system_error').' #15');
		}

		return array(TRUE,$this->mod->Lang('login_changed'));
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

	/* *
	 * Verifies a captcha code
	 * @captcha string
	 * Returns: boolean
	 */
/*	protected function checkCaptcha($captcha)
	{
		return TRUE;
	}
*/
	/**
	* Adds an attempt to database
	* Returns: boolean indicating success
	*/
	protected function addAttempt()
	{
		$ip = $this->getIp();
		$val = $this->getConfig($this->context,'attack_mitigation_time');
		$attempt_expire = date('Y-m-d H:i:s', strtotime($val)); //TODO zone
		$sql = 'INSERT INTO '.$this->pref.'module_auth_attempts (ip,expire) VALUES (?,?)';
		$res = $this->db->execute($sql,array($ip,$attempt_expire));
		return ($res != FALSE);
	}

	/**
	* Deletes some/all attempts for a given IP from database
	* @ip string $
	* @all boolean default = FALSE
	* Returns: boolean indicating success
	*/
	protected function deleteAttempts($ip, $all=FALSE)
	{
		if ($all) {
			$sql = 'DELETE FROM '.$this->pref.'module_auth_attempts WHERE ip=?';
			$res = $this->db->execute($sql,array($ip));
			return ($res != FALSE);
		}

		$sql = 'SELECT id,expire FROM '.$this->pref.'module_auth_attempts WHERE ip=?';
		$data = $this->db->GatArray($sql,array($ip));
		$sql = 'DELETE FROM '.$this->pref.'module_auth_attempts WHERE id=?';
		$res = TRUE;
		foreach ($data as $row) {
			$expire = strtotime($row['expire']); //TODO
			$nowtime = strtotime(date('Y-m-d H:i:s')); //TODO zone independence
			if ($nowtime > $expire) {
				$res = $this->db->execute($sql,array($row['id'])) && $res;
			}
		}
		return $res;
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
