<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
namespace Auther;

class Session
{
	//status codes:
	const NEW_FOR_USER = 1;
	const NEW_FOR_IP = 2;
	const RESET_REQUESTED = 3;
	const WAIT_CONFIRM = 4;
	const WAIT_CHALLENGE = 5;
	const ATTEMPT_FAILED = 10;
	const BAD_IP = 11;
	const BLOCKED_IP = 12;

	protected $mod;
	protected $db;
	protected $pref;
	protected $context; //numeric id

	public function __construct(&$mod, $context=0)
	{
		$this->mod = $mod;
		$this->db = \cmsms()->GetDb();
		$this->pref = \cms_db_prefix();
		$this->context = $context;
	}

	/**
	* Gets the current session (if any) for user @uid
	* Returns: string session-token, or FALSE
	*/
	public function GetUserSession($uid)
	{
		$sql = 'SELECT token FROM '.$this->pref.'module_auth_sessions WHERE user_id=? AND context_id=?';
		return $this->db->GetOne($sql, [$uid, $this->context]);
	}

	/**
	* Gets the current session (if any) for source @ip
	* Returns: string session-token, or FALSE
	*/
	public function GetSourceSession($ip)
	{
		$sql = 'SELECT token FROM '.$this->pref.'module_auth_sessions WHERE ip=? AND context_id=?';
		return $this->db->GetOne($sql,  [$ip, $this->context]);
	}

	/**
	* Gets all parameters for the session having @token
	* Returns: array, or FALSE
	*/
	public function GetSessionData($token)
	{
		$sql = 'SELECT * FROM '.$this->pref.'module_auth_sessions WHERE token=?';
		return $this->db->GetRow($sql, [$token]);
	}

	/**
	* Creates a session for user @uid
	* Returns: string session-token
	*/
	public function MakeUserSession($uid, $remember=TRUE)
	{
		$ip = $this->GetIp();
		$data = $this->AddSession($uid, $ip, $remember);
		return $data['token'];
	}

	/**
	* Creates a session for source @ip
	* Returns: string session-token
	*/
	public function MakeSourceSession($ip, $remember=TRUE)
	{
		$data = $this->AddSession(FALSE, $ip, $remember);
		return $data['token'];
	}

	/**
	* Creates a session for user @uid/source @ip
	* @uid: int user enumerator or FALSE
	* @ip: source ip address (V4 or 6)
	* @remember: boolean whether to setup an expiry time for the session
	* Returns: array with members 'token','cookie_token','expire','expiretime', or else FALSE
	*/
	protected function AddSession($uid, $ip, $remember)
	{
		if ($uid) {
			$sql = 'SELECT id FROM '.$this->pref.'module_auth_users WHERE id=? AND active>0';
			if (!$this->db->GetOne($sql, [$uid])) {
				return FALSE;
			}
			$this->DeleteUserSessions($uid);
		} else {
			$this->DeleteSourceSessions($ip);
		}

		$token = $this->UniqueToken(24);
		$val = $this->mod->GetPreference('session_salt');
		$data = ['token'=>$token,'cookie_token'=>sha1($token.$val)];

		$dt = new \DateTime('@'.time(), NULL);
		if ($remember) {
			$val = $this->GetConfig('cookie_remember');
			$dt->modify('+'.$val);
			$data['expire'] = $dt->getTimestamp();
			$data['expiretime'] = $data['expire'];
		} else {
			$val = $this->GetConfig('cookie_forget');
			$dt->modify('+'.$val);
			$data['expire'] = $dt->getTimestamp();
			$data['expiretime'] = 0;
		}

		$cid = $TODO;
		$stat = ($uid) ? self::NEW_FOR_USER : self::NEW_FOR_IP;
		if (!$uid) {
			$uid = NULL;
		}
		$agent = $_SERVER['HTTP_USER_AGENT'];

		$sql = 'INSERT INTO '.$this->pref.
'module_auth_sessions (token,ip,user_id,context_id,expire,lastmode,attempts,cookie_hash,agent) VALUES (?,?,?,?,?,?,?,?,?)';
		$args = [$token, $ip, $uid, $this->context, $data['expire'], $stat, 1, $data['cookie_token'], $agent];

		if (!$this->db->Execute($sql, $args)) {
			return FALSE;
		}

		return $data;
	}

	/**
	* Removes all existing sessions for user @uid
	* @uid: int user enumerator
	* Returns: boolean
	*/
	protected function DeleteUserSessions($uid)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE user_id=?';
		$res = $this->db->Execute($sql, [$uid]);
		return ($res != FALSE);
	}

	/**
	* Removes all existing sessions for src @ip
	* @ip: source ip address (V4 or 6)
	* Returns: boolean
	*/
	protected function DeleteSourceSessions($ip)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE ip=?';
		$res = $this->db->Execute($sql, [$uid]);
		return ($res != FALSE);
	}

	/**
	* Removes a session identified by @token
	* @token: string
	* Returns: boolean
	*/
	protected function DeleteSession($token)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE token=?';
		$res = $this->db->Execute($sql, [$token]);
		return ($res != FALSE);
	}

	/**
	* Checks if a session is valid
	* @token: string 24-byte session identifier
	* Returns: boolean
	*/
	public function CheckSession($token)
	{
		$block_status = $this->IsBlocked();

		if ($block_status == 'block') {
			return FALSE;
		}

		if (strlen($token) != 24) {
			return FALSE;
		}

		$sql = 'SELECT id,user_id,expire,ip,agent,cookie_token FROM '.$this->pref.'module_auth_sessions WHERE token=?';
		$row = $this->db->GetRow($sql, [$token]);

		if (!$row) {
			return FALSE;
		}

		if ($row['expire'] < time()) {
			$this->DeleteExistingSessions($row['uid']);
			return FALSE;
		}

		$ip = $this->GetIp();
		if ($ip != $row['ip']) {
			return FALSE;
		}

		$val = $this->mod->GetPreference('session_salt');
		return ($row['cookie_token'] == sha1($token.$val));
	}

	/**
	* Sets the user-enumerator associated with the given session-token (after a
	* @token: string identifier
	* @uid: user enumerator
	* Returns: nothing
	*/
	public function setSessionUID($token, $uid)
	{
		$sql = 'UPDATE '.$this->pref.'module_auth_sessions SET user_id=? WHERE token=?';
		$this->db->Execute($sql, [$uid, $token]);
		$sql = 'UPDATE '.$this->pref.'module_auth_sessions SET lastmode=? WHERE token=? AND lastmode=?';
		$this->db->Execute($sql, [self::NEW_FOR_USER, $token, self::NEW_FOR_IP]); //maybe does nothing
	}

	/**
	* Retrieves the user-enumerator associated with the given session-token
	* @token: string
	* Returns: int, or maybe '' if user not recorded yet
	*/
	public function getSessionUID($token)
	{
		$sql = 'SELECT user_id FROM '.$this->pref.'module_auth_sessions WHERE token=?';
		return $this->db->GetOne($sql, [$token]);
	}

	/**
	@set FALSE to get data, timstamp or YmdHis-formatted string to set data
	@raw optional boolean whether to set/get timestamp instead of D/T string, default FALSE
	*/
	public function LatestLogin($token, $set, $raw=FALSE)
	{
		if ($set) {
			if ($raw) {
				$st = $set;
			} else {
				$st = 0; //TODO convert from Ymd His string
			}
			$sql = 'UPDATE '.$this->pref.'module_auth_users U JOIN '.$this->pref.
			'module_auth_sessions S ON U.id = S.user_id SET set U.lastuse=? WHERE S.token=?';
			$this->db->Execute($sql, [$st, $token]);
		} else {
			//TODO CHECK can there be >1 session for the user?
			$sql = 'SELECT U.lastuse FROM '.$this->pref.'module_auth_users U JOIN '.
			$this->pref.'module_auth_sessions S ON U.id = S.user_id WHERE S.token=?';
			$st = $this->db->GetOne($sql, [$token]);
			if ($raw) {
				return $st;
			} else {
				//TODO format as Ymd His
				return 'TODO Ymd His';
			}
		}
	}

	public function GetAttempts($token)
	{
		$sql = 'SELECT attempts FROM '.$this->pref.'module_auth_sessions WHERE token=?';
		return $this->db->GetOne($sql, [$token]);
	}

	public function BumpAttempts($token)
	{
		$sql = 'UPDATE '.$this->pref.'module_auth_sessions SET attempts=attempts+1 WHERE token=?';
		$this->db->Execute($sql, [$token]);
	}

	/**
	* Adds an attempt to the session related to the current source ip address
	* Returns: Nothing
	*/
	public function AddAttempt()
	{
		$dt = new \DateTime('@'.time(), NULL);
		$val = $this->GetConfig('attack_mitigation_span');
		$dt->modify('+'.$val);
		$expiry = $dt->getTimestamp();

		$ip = $this->GetIp();
		$token = $this->GetSourceSession($ip);
		if ($token) {
		//SESSION STATUS CHANGE?
			$sql = 'UPDATE '.$this->pref.'module_auth_sessions SET expire=?, attempts=attempts+1 WHERE token=?';
			$this->db->Execute($sql, [$expiry, $token]);
		} else {
			$token = $this->MakeSourceSession($ip);
			$sql = 'UPDATE '.$this->pref.'module_auth_sessions SET expire=? WHERE token=?';
			$this->db->Execute($sql, [$expiry, $token]);
		}
	}

	/**
	* Deletes expired|all attempts for a given IP from session(s) data
	* @ip: string source ip address
	* @all: optional boolean whether to delete only expired attempts, default = FALSE
	* Returns: boolean indicating success
	*/
	public function DeleteAttempts($ip, $all=FALSE)
	{
		if ($all) {
			$sql = 'UPDATE '.$this->pref.'module_auth_sessions SET attempts=0 WHERE ip=?';
			$res = $this->db->Execute($sql, [$ip]);
		} else {
			$sql = 'UPDATE '.$this->pref.'module_auth_sessions SET attempts=0 WHERE ip=? AND expire<?';
			$nowtime = time();
			$res = $this->db->Execute($sql, [$ip, $nowtime]);
		}
		return ($res != FALSE);
	}

	/**
	* Gets current session token
	* Not to be confused with GetUserSession() etc
	* Returns: string
	*/
	public function GetSessionToken()
	{
		$val = $this->GetConfig('cookie_name');
		return $_COOKIE[$val];
	}

	/**
	* Get IP address
	* Returns: string $ip
	*/
	protected function GetIp()
	{
		if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			return $_SERVER['HTTP_X_FORWARDED_FOR'];
		} else {
			return $_SERVER['REMOTE_ADDR'];
		}
	}

	/**
	* Get specified property(ies) for the current context
	* @propkey: string property-name or array of them (not validated here)
	* Returns: property value or assoc. array of them
	*/
	protected function GetConfig($propkey)
	{
		if ($this->context) {
			if (is_array($propkey)) {
				$sql2 = implode(',', $propkey);
			} else {
				$sql2 = $propkey;
			}
			if (is_int($this->context)) {
				$sql3 = 'id';
			} else {
				$sql3 = 'alias';
			}

			$sql = 'SELECT '.$sql2.' FROM '.$this->pref.'module_auth_contexts WHERE '.$sql3.'=?';
			$data = $this->db->GetRow($sql, [$this->context]);
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
	* Reports access-status for the current ip address
	* Returns: string 'allow','verify' or 'block'
	*/
	public function IsBlocked()
	{
		$ip = $this->GetIp();
		$this->DeleteAttempts($ip, FALSE);
		$sql = 'SELECT COUNT(1) AS tries FROM '.$this->pref.'module_auth_attempts WHERE ip=?';
		$tries = $this->db->GetOne($sql, [$ip]);

		$val = (int)$this->GetConfig('attempts_before_verify');
		if ($val > 0 && $tries < $val) {
			return 'allow';
		}

		$val = (int)$this->GetConfig('attempts_before_ban');
		if ($val > 0 && $tries < $val) {
			return 'verify';
		}

		return 'block';
	}

	/**
	* Returns a random(ish) string (not as diverse as from Setup::UniqueToken())
	* @length: int wanted byte-count (>=13) for the string
	* Returns: string
	*/
	public function UniqueToken($length)
	{
		$s1 = uniqid();
		$l1 = strlen($s1);
		$l2 = $length - $l1;
		if ($l2 > 0) {
			$chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
			$s2 = str_repeat('0', $l2);
			for ($i = 0; $i < $l2; $i++) {
				$s2[$i] = $chars[mt_rand(0, 71)];
			}
		} else {
			$s2 = '';
		}
		return str_shuffle($s2.$s1);
	}
}
