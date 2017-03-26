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
*/

class Challenge extends Session
{
	public function __construct(&$mod, $context=0)
	{
		parent::__construct($mod, $context);
	}

	//~~~~~~~~~~~~~ RESPONSES ~~~~~~~~~~~~~~~~~

	/**
	* Activates a user's account after a valid challenge-response
	*
	* @token: string 24-byte token
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function Activate($token)
	{
		switch ($this->GetStatus()) {
		 case parent::STAT_BLOCK:
			return [FALSE, $this->mod->Lang('user_blocked')];
		 case parent::STAT_CHALLENGE:
			return [FALSE, $this->mod->Lang('user_challenged')];
		}

		if (strlen($token) !== 24) {
			$this->AddAttempt();
			return [FALSE, $this->mod->Lang('invalid_activationkey')];
		}

		$data = $this->GetChallenge($token, 'activate');

		if (!$data[0]) {
			$this->AddAttempt();
			return $data;
		}

		$userdata = $this->GetUserBase($data['uid']); //TODO wrong class
		if ($userdata['active']) {
			$this->AddAttempt();
			$this->DeleteChallenge($token);
			return [FALSE, $this->mod->Lang('system_error', '#51')];
		}

		$sql = 'UPDATE '.$this->pref.'module_auth_users SET active=1 WHERE id=?';
		$this->db->Execute($sql, [$data['uid']]);

		$this->DeleteChallenge($token);

		return [TRUE, $this->mod->Lang('activation_success')];
	}

	/**
	 * If action-status warrants or @check=FALSE, resets a user's password
	 *
	 * @token: string 24-byte token
	 * @newpass: plaintext string
	 * @repeatnewpass: plaintext string
	 * Returns: array [0]=boolean for success, [1]=message or ''
	 */
	public function ResetPassword($token, $newpass, $repeatnewpass)
	{
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

		if (strlen($token) != 24) {
			return [FALSE, $this->mod->Lang('invalid_resetkey')];
		}

		$data = $this->GetChallenge($token, 'reset'); //TODO no challenges here

		if (!$data[0]) {
			return $data;
		}

		$status = $this->matchPassword($data['uid'], $newpass);

		if (!$status[0]) {
			return $status;
		}

		if ($newpass !== $repeatnewpass) {
			// Passwords don't match
			return [FALSE, $this->mod->Lang('newpassword_nomatch')];
		}

		$userdata = $this->GetUserBase($data['uid']);

		if (!$userdata) {
			$this->AddAttempt();
			$this->DeleteChallenge($token); //TODO no challenges here
			return [FALSE, $this->mod->Lang('system_error', '#12')];
		}

		if ($this->DoPasswordCheck($newpass, $userdata['password']/*, $tries TODO*/)) {
			$this->AddAttempt();
			return [FALSE, $this->mod->Lang('newpassword_match')];
		}

		$newpass = password_hash($newpass, PASSWORD_DEFAULT);
		$sql = 'UPDATE '.$this->pref.'module_auth_users SET privhash=? WHERE id=?';
		$res = $this->db->Execute($sql, [$newpass, $data['uid']]);

		if ($res) {
			$this->DeleteChallenge($token); //TODO no challenges here
			return [TRUE, $this->mod->Lang('password_reset')];
		}
		return [FALSE, $this->mod->Lang('system_error', '#13')];
	}

	//~~~~~~~~~~~~~ CHALLENGES ~~~~~~~~~~~~~~~~~

	/**
	* If action-status warrants or @check=FALSE, records a challenge of the specified type
	*
	* @login: string user identifier
	* @type: string 'activate','change','reset' or 'delete'
	* @data: optional string, context-specific data to be cached, default = NULL
	* Returns: array [0]=boolean for success, [1]=message or '' or challenge-token
	* @check: optional boolean whether to check action-status before proceeding default = TRUE
	*/
	protected function AddChallenge($login, $type, $data=NULL, $check=TRUE)
	{
		if ($check) {
			switch ($this->GetStatus()) {
			 case parent::STAT_BLOCK:
				return [FALSE, $this->mod->Lang('user_blocked')];
			 case parent::STAT_CHALLENGE:
				return [FALSE, $this->mod->Lang('user_challenged')];
			}
		}

		switch ($type) {
		 case 'activate':
			$itype = parent::CHALL_ACTIV; //'interim' identifier, pending token
			break;
		 case 'change':
			$itype = parent::CHALL_CHANGE;
			break;
		 case 'reset':
			$itype = parent::CHALL_RESET;
			break;
		 case 'delete':
			$itype = parent::CHALL_DELETE;
			break;
		 default:
			return [FALSE, $this->mod->Lang('system_error', '#52')];
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
					return [FALSE, $this->mod->Lang('temp_notsent')];
				}
			}
		} else {
			return [FALSE, $this->mod->Lang('system_error', '#53')];
		}

		if ($type == 'activate') {
			if ($row['active']) {
				return [FALSE, $this->mod->Lang('already_activated')];
			}
		}

		$sql = 'SELECT token,expire FROM '.$this->pref.'module_auth_cache WHERE user_id=? AND lastmode=?';
		$row = $this->db->GetRow($sql, [$uid, $itype]);

		if ($row) {
			if ($row['expire'] > time()) {
				return [FALSE, $this->mod->Lang('request_exists')];
			}
			$this->DeleteChallenge($row['token']);
		}

		$token = $this->UniqueToken(24);

		$dt = new \DateTime('@'.time(), NULL);
		$val = $this->GetConfig('request_key_expiration');
		$dt->modify('+'.$val);
		$expiretime = $dt->getTimestamp();

		$sql = 'INSERT INTO '.$this->pref.'module_auth_cache (token,user_id,expire,lastmode,data) VALUES (?,?,?,?,?)';

		if (!$this->db->Execute($sql, [$token, $uid, $expiretime, $itype, $data])) {
			return [FALSE, $this->mod->Lang('system_error', '#54')];
		}

		return [TRUE, $token];
	}

	/**
	* Gets subset of challenge data if @token is valid
	*
	* @token: 24-byte string from UniqueToken()
	* @type: string 'reset','change' or 'activate', only for error-message namespacing
	* Returns: array [0]=boolean for success, [1]=message or '', if [0] then also 'uid'
	*/
	public function GetChallenge($token, $type)
	{
		$sql = 'SELECT user_id,expire FROM '.$this->pref.'module_auth_cache WHERE token=?';
		$row = $this->db->GetRow($sql, [$token]);

		if (!$row) {
			$this->AddAttempt();
			return [FALSE, $this->mod->Lang('incorrect_'.$type.'key')];
		}

		if ($row['expire'] < time()) {
			$this->AddAttempt();
			$this->DeleteChallenge($token);
			return [FALSE, $this->mod->Lang($type.'key_expired')];
		}

		return [0=>TRUE, 1=>'', 'uid'=>$row['uid']];
	}

	/**
	* Deletes a challenge
	*
	* @token: string challenge identifier
	* Returns: boolean
	*/
	protected function DeleteChallenge($token)
	{
		$sql = 'DELETE FROM '.$this->pref.'module_auth_cache WHERE token=?';
		$this->db->Execute($sql, [$token]);
		return ($this->db->Affected_Rows() > 0);
	}

	/**
	* Sends an email challenge
	*
	* @type: string 'reset','activate','change' or 'delete' used to specify lang keys
	* @token: optional string to be delivered to user instead of an URL, default = FALSE
	* Returns: array [0]=boolean for success, [1]=message or ''
	*/
	public function ChallengeMessage($type, $token=FALSE)
	{
		if ($this->mod->before20) {
			$mlr = \cms_utils::get_module('CMSMailer');
			if ($mlr) {
				$mlr->_load();
			} else {
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
		$part = $this->mod->Lang('email_subject_'.$type);
		$mlr->SetSubject($this->mod->Lang('email_subject', $site, $part));

		$part = $this->mod->Lang('email_do_'.$type);
		$part2 = $this->mod->Lang('email_request_'.$type);

		if ($token) {
			$mlr->SetBody($this->mod->Lang('email_token_body', $part, $token, $part2, $site));
			$mlr->SetAltBody($this->mod->Lang('email_token_altbody', $part, $token, $part2, $site));
		} else {
			//construct frontend-url (so no admin login is needed)
			$u = $this->mod->create_url('cntnt01', 'validate', '', ['cauthc'=>$token]);
			$url = str_replace('&amp;', '&', $u);

			$mlr->SetBody($this->mod->Lang('email_url_body', $part, $url, $part2, $site));
			$mlr->SetAltBody($this->mod->Lang('email_url_altbody', $part, $url, $part2, $site));
		}

		if ($mlr->Send()) {
			$mlr->reset();
			return [TRUE, ''];
		} else {
			$msg = $mlr->GetErrorInfo();
			$mlr->reset();
			return [FALSE, $msg];
		}
	}
}
