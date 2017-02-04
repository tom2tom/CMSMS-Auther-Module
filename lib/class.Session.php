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
	protected $context;

	public function __construct(&$mod, $context=NULL)
	{
		$this->mod = $mod;
		$this->db = \cmsms()->GetDb();
		$this->pref = \cms_db_prefix();
		$this->context = $context;
	}

	public function GetUserSession($uid)
	{
	}

	public function GetSourceSession($ip)
	{
	}

	public function GetSession($token)
	{
	}

	public function UpdateSession($token)
	{
	}

	public function LatestLogin($token, $set)
	{
	}

	public function GetTries($token)
	{
	}

	public function BumpTries($token)
	{
	}

	/**
	* Adds an attempt to database
	* TODO @token session identifier
	* Returns: boolean indicating success
	*/
	public function AddAttempt()
	{
		$ip = $this->GetIp();
		$dt = new \DateTime('@'.time(), NULL);
		$val = $this->GetConfig('attack_mitigation_span');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$sql = 'INSERT INTO '.$this->pref.'module_auth_attempts (ip,expire) VALUES (?,?)';
		$res = $this->db->Execute($sql, [$ip, $expiretime]);
		return ($res != FALSE);
	}

	/**
	* Deletes some/all attempts for a given IP from database
	* @ip: string
	* @all: boolean default = FALSE
	* Returns: boolean indicating success
	*/
	public function DeleteAttempts($ip, $all=FALSE)
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

	public function MakeUserSession($uid)
	{
	}

	public function MakeSourceSession($ip)
	{
	}

	/**
	* Creates a session for user @uid
	* @uid: int user enumerator
	* @remember: boolean whether to setup an expiry time for the session
	* Returns: array with members 'token','expire','expiretime','cookie_token', or else FALSE
	*/
	protected function AddSession($uid, $remember)
	{
		$sql = 'SELECT uid FROM '.$this->pref.'module_auth_users WHERE id=? AND active>0';
		if (!$this->db->GetOne($sql, [$uid])) {
			return FALSE;
		}

		$this->DeleteExistingSessions($uid);

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

		$ip = $this->GetIp();
		$agent = $_SERVER['HTTP_USER_AGENT'];

		$sql = 'INSERT INTO '.$this->pref.'module_auth_sessions (uid,token,expire,ip,agent,cookie_token) VALUES (?,?,?,?,?,?)';

		if (!$this->db->Execute($sql, [$uid, $token, $data['expire'], $ip, $agent, $data['cookie_token']])) {
			return FALSE;
		}

		return $data;
	}

	/**
	* Removes all existing sessions for user @uid
	* @uid: int user enumerator
	* Returns: boolean
	*/
	protected function DeleteExistingSessions($uid)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_sessions WHERE uid=?';
		$res = $this->db->Execute($sql, [$uid]);
		return ($res != FALSE);
	}

	public function RemoveSession($token)
	{
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

		$sql = 'SELECT id,uid,expire,ip,agent,cookie_token FROM '.$this->pref.'module_auth_sessions WHERE token=?';
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
	* Retrieves the user-enumerator associated with the given session-token
	* @token: string
	* Returns: int
	*/
	public function getSessionUID($token)
	{
		$sql = 'SELECT uid FROM '.$this->pref.'module_auth_sessions WHERE token=?';
		return $this->db->GetOne($sql, [$token]);
	}

	/**
	* Gets current session token
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
