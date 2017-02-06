<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

/*TODO get & process $_POST array e.g.
[pA762_jsworks]	"TRUE" iff ajax-sourced
[pA762_submit]	"Submit" iff NOT ajax-sourced
[pA762_captcha]	"text" maybe iff NOT ajax-sourced
[pA762_login]	"rogerrabbit"
[pA762_login2]	"somethingorempty"
[pA762_passwd]	"passnow" iff NOT ajax-sourced
[pA762_recover]	"0" OR "1" if 1, only login value is relevant
[pA762_name]	"whateverorempty"
[pA762_contact]	"whateverorempty"
$sent array iff ajax-sourced
[passwd] => "passnow"
*/

//TODO handle force-reset flag for user
if (empty($_POST[$id.'recover'])) {
	$flds = [];
	$lvl = $cdata['security_level'];
	switch ($lvl) {
	 case Auther\Setup::NOBOT:
		//nothing to do
		break;
	 case Auther\Setup::LOSEC:
	 case Auther\Setup::NONCED:
	 case Auther\Setup::CHALLENGED:
		//common stuff
		$login = trim($_POST[$id.'login']);
		$t = ($jax) ? $sent['passwd'] : $_POST[$id.'passwd'];
		$pw = trim($t);
		$res = $vfuncs->IsKnown($login, $pw);
		if (!$res[0]) {
			$msgs[] = $res[1];
			$focus = 'login';
		}
		$t = trim($_POST[$id.'login2']);
		if ($t) {
			$res = $afuncs->validateLogin($t);
			if ($res[0]) {
				if ($afuncs->isLoginTaken($t)) {
					$msgs[] = $mod->Lang('login_notvalid'); //NOT explicit in-use message!
					$focus = 'login2';
				} else {
					$flds['publicid'] = $t;
				}
			} else {
				$msgs[] = $res[1];
				if (!$focus) { $focus = 'login2'; }
			}
		}
		$t = trim($_POST[$id.'name']);
		if ($t) {
//			$t = X::SanitizeName($t); TODO cleanup whitespace etc
			$res = $afuncs->validateName($t);
			if ($res[0]) {
				$flds['name'] = $t; //crypt if/when needed
			} else {
				$msgs[] = $res[1];
				if (!$focus) { $focus = 'name'; }
			}
		}
		$t = trim($_POST[$id.'contact']);
		if ($t) {
			$res = $afuncs->validateAddress($t);
			if ($res[0]) {
				$flds['address'] = $t; //crypt if/when needed
			} else {
				$msgs[] = $res[1];
				if (!$focus) { $focus = 'contact'; }
			}
		}
		switch ($lvl) {
		 case Auther\Setup::NONCED:
		//check stuff
			if (!$jax) {
				if ($params['captcha'] !== $_POST[$id.'captcha']) {
					$msgs[] = $mod->Lang('err_captcha');
					if (!$focus) { $focus = 'captcha'; }
				}
			}
			break;
		 case Auther\Setup::CHALLENGED:
		//check stuff
			if (!$jax) {
			}
			break;
		}
		break;
	 case Auther\Setup::HISEC:
	 //TODO
		break;
	}

	if (!$msgs) {
		if ($lvl == Auther\Setup::CHALLENGED) {
		//cache provided data (from $flds[] to session::cache)
		//also current login etc or uid
		//initiate challenge
		} else {
		//record requested changes
		//report success
		}
	}
} else { //recovery-request
	$login = trim($_POST[$id.'login']);
	$token = $params['token'];
	$res = $vfuncs->DoRecover($login, $token); //might not return
//TODO update stuff eg token
	if ($res[0]) {
		//report success ?
		exit;
	} else {
		$msgs[] = $res[1];
	}
}
