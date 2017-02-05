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
		if (!$afuncs) {
			$afuncs = new Auth($mod, NULL); //TODO some relevant context
		}
		$this->afuncs = $afuncs;
		if (!$cfuncs) {
			$cfuncs = new Crypter();
		}
		$this->cfuncs = $cfuncs;
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
	 * Checks validity of decryted @val using Auth::@authmethod
	 * Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	 */
	public function CheckEncrypted($val, $authmethod, $failkey=FALSE)
	{
		$val = $this->cfuncs->decrypt_value($this->mod, $val);
		return $this-CheckValue($val, $authmethod, $failkey);
	}

	/**
	 * Checks validity of supplied password
	 * Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	 */
	public function CheckPassword($val, $session, $failkey='err_parm')
	{
		$uid = 22; //TODO get from session
		$res = $this->afuncs->getBaseUser($uid);
		if ($res && $res['active']) {
			$tries = 1; //TODO get from session
			if ($this->afuncs->password_check($val, $res['privhash'], $tries)) {
				return [TRUE,''];
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
	 * Checks validity of suppplied login and password
	 * @passwd may be FALSE, so as to check only the login
	 * Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	 */
	public function IsKnown($login, $passwd, $failkey='authority_failed')
	{
		if ($this->afuncs->isRegistered($login, $passwd))
			return [TRUE,''];
		}

		if (is_array($failkey)) {
			$msg = $this->CompoundMessage($failkey);
		} else {
			$msg = $this->mod->Lang($failkey);
		}
		return [FALSE, $msg];
	}

	/**
	* Initiate password recovery if the supplied login is known
	* Normally do not provide $failkey
	* Returns: 2-member array, [0] = boolean indicating success, [1] = error message or ''
	*/
	public function DoRecover($login, &$token, $failkey='err_parm')
	{
		$res = $this->IsKnown($login, FALSE, $failkey);
		if ($res[0]) {
			//TODO iff context::send_reset_message
			$userdata = $this->afuncs->getPublicUser($login);
			if (preg_match('//', $userdata['address'])) {
				$sendmail = $userdata['address'];
			elseif (preg_match('//', $login)) {
				$sendmail = login;
			} else {
				$sendmail = FALSE;
			}
			if ($sendmail) {
			// send message
				if ($token) {
		//	cache stuff in current session 
				} else {
		//	make new session
		//	cache stuff in new session 
				}
			// setup for downstream message
				if ($jax) {
			//	send ['replace'=>'authelements','html'=>'X','message'=>'X']
				} else {
			//	send token to handler 
				}
				return [TRUE,''];
			} elseif (0) { //can setup for sync reset
			// set/update session as above
		//TODO
				if ($jax) {
			//	send ['replace'=>'authelements','html'=>'X','message'=>'X']
				} else {
			//	send token to handler 
				}
				return [TRUE,''];
			} else {
				if (is_array($failkey)) {
					$msg = $this->CompoundMessage($failkey);
				} else {
					$msg = $this->mod->Lang($failkey);
				}
				return [FALSE, $msg];
			}
		} else { //login not recognised
			if ($token) {
				$tries = $this->afuncs->BumpTries($token);
//				TODO handle if too many
			} else {
				$ip = $this->afuncs->GetIp();
				$token = $this->afuncs->MakeSourceSession($ip); //upstream gets it too
				$this->afuncs->BumpTries($token); //1 attempt sofar
			}
			return [FALSE, $res[1]];
		}
	}
}
