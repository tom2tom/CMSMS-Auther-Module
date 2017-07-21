<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
namespace Auther;

class Validate
{
	protected $mod;
	protected $afuncs;
	protected $cfuncs;

	public function __construct(&$mod, &$afuncs=NULL, &$cfuncs=NULL)
	{
		$this->mod = $mod;
		$this->afuncs = ($afuncs) ? $afuncs : new Auth($mod); //TODO some relevant context
		$this->cfuncs = ($cfuncs) ? $cfuncs : new Crypter($mod);
	}

	protected function CompoundMessage($args)
	{
		$c = count($args);
		for ($i = 1; $i < $c; $i++) {
			$args[$i] = $this->mod->Lang($args[$i]);
		}
		return call_user_func_array(array($this->mod, 'Lang'), $args);
	}

	/**
	 * Checks validity of @val using Auth::@authmethod
	 * Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	 */
	public function CheckValue($val, $authmethod, $failkey=FALSE)
	{
		$res = $this->afuncs->$authmethod($val);
		if ($res[0]) {
			return $res;
		}

		if ($failkey) {
			if (is_array($failkey)) {
				$res[1] = $this->CompoundMessage($failkey);
			} else {
				$res[1] = $this->mod->Lang($failkey);
			}
		} elseif (!$res[1]) {
			$res[1] = $this->mod->Lang('err_parm');
		}
		return $res;
	}

	/**
	 * Checks validity of uncloaked @val using Auth::@authmethod
	 * Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	 */
	public function CheckEncrypted($val, $authmethod, $failkey=FALSE)
	{
		$val = $this->cfuncs->uncloak_value($val);
		return $this->CheckValue($val, $authmethod, $failkey);
	}

	/**
	 * Checks validity of supplied password @val
	 * Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	 */
	public function CheckPassword($val, $session, $failkey='err_parm')
	{
		$uid = 22; //TODO get from session
		$res = $this->afuncs->GetUserBase($uid);
		if ($res && $res['active']) {
			$tries = 1; //TODO get from session
			if ($this->afuncs->DoPasswordCheck($val, $res['passhash'], $tries, $uid)) {
				return [TRUE, ''];
			}
		}

		if (is_array($failkey)) {
			$msg = $this->CompoundMessage($failkey);
		} else {
			$msg = $this->mod->Lang($failkey);
		}
		return [FALSE, $msg];
	}

	/**
	 * Checks validity of supplied login and password
	 * @passwd may be FALSE, so as to check only the login
	 * Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	 */
/*	public function IsKnown($login, $passwd, $failkey='incorrect_vague')
	{
		$res = $this->afuncs->IsRegistered($login, $passwd); //TRUE, FALSE, $token);
		if ($res[0]) {
			return [TRUE, ''];
		}

		if (is_array($failkey)) {
			$msg = $this->CompoundMessage($failkey);
		} else {
			$msg = $this->mod->Lang($failkey);
		}
		return [FALSE, $msg];
	}
*/
	/**
	 * Cleans up @name
	 * @enc optional string char-encoding of @name, default = 'UTF-8'
	 * Returns: string
	 */
	public function SanitizeName($name, $enc='UTF-8')
	{
		$t = trim($name);
		$t = preg_replace('/\s{1,}/', ' ', $t);
		//stet what may be a short capitalised acronym
		if (strpos($t,' ') !== FALSE || strlen($t) > 5) {
			if (extension_loaded('mbstring')) {
				$t = mb_convert_case($t, MB_CASE_TITLE, $enc);
			} else {
				$t = ucwords($t);
			}
		}
		return $t;
	}

	/**
	 * Eliminates from @string some of the more egregious injections, if found
	 * This supports a fuck-off hint to crackers, the real protection is query-parameterisation
	 * @string: string to be checked, maybe FALSE
	 * Returns: boolean indicating @string passes the tests, TRUE if @string is FALSE
	 */
	public function FilteredPassword($string)
	{
		if ($string) {
			$t = filter_var($string, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);
			return $t === $string;
		}
		return TRUE;
	}

	/**
	 * Evaluates @string to check for some of the more egregious injections
	 * This supports a fuck-off hint to crackers, the real protection is query-parameterisation
	 * @string: (un-quoted) string to be checked, maybe FALSE
	 * Returns: boolean indicating @string passes the tests, TRUE if @string is FALSE
	 */
	public function FilteredString($string)
	{
		if ($string) {
			$t = filter_var($string, FILTER_UNSAFE_RAW,
				FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_BACKTICK);
			if ($t !== $string) {
				return FALSE;
			}
			$t = preg_replace('/[\'"]\s?;/', '', $t);
			if ($t !== $string) {
				return FALSE;
			}
			$t = addslashes($t);
			return $t === $string;
		}
		return TRUE;
	}

	/**
	 * Checks whether a user has been flagged for a forced password-reset
	 * The user's active flag is ignored
	 * Must supply valid @uid, or @login and @cid
	 * @uid: user identifier or FALSE
	 * @login: optional alternative user identifier or FALSE
	 * @cid: optional numeric context indentifier for use with @login, otherwise ignored
	 * Returns: boolean
	 */
	public function IsForced($uid, $login=FALSE, $cid=FALSE)
	{
		$pref = \cms_db_prefix();
		if ($uid) {
			$sql = 'SELECT 1 FROM '.$pref.'module_auth_users WHERE id=? AND passreset>0';
			return \cmsms()->GetDb()->GetOne($sql, [$uid]);
		} elseif ($login) {
			$hash = $this->cfuncs->hash_value($login);
			$sql = 'SELECT 1 FROM '.$pref.'module_auth_users WHERE acchash=? AND context_id=? AND passreset>0';
			return \cmsms()->GetDb()->GetOne($sql, [$hash, $cid]);
		}
	}

	/**
	 * Sets forced-password-reset flag for a user
	 * @state: int 0 or 1, the new setting
	 * @uid: user identifier or FALSE
	 * @login: optional alternative user identifier or FALSE
	 * @cid: optional numeric context indentifier for use with @login, otherwise ignored
	 * Returns: nothing
	 */
	public function SetForced($state, $uid, $login=FALSE, $cid=FALSE)
	{
		$pref = \cms_db_prefix();
		if ($uid) {
			$sql = 'UPDATE '.$pref.'module_auth_users SET passreset=? WHERE id=?';
			\cmsms()->GetDb()->Execute($sql, [$state, $uid]);
		} elseif ($login) {
			$hash = $this->cfuncs->hash_value($login);
			$sql = 'UPDATE '.$pref.'module_auth_users SET passreset=? WHERE acchash=? AND context_id=?';
			\cmsms()->GetDb()->Execute($sql, [$state, $hash, $cid]);
		}
	}
}
