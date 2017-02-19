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
[pA762_passwd]	"passnow" iff NOT ajax-sourced
[pA762_passwd2]	"someother" iff NOT ajax-sourced, should not be same as 1
[pA762_passwd3]	"someother" iff NOT ajax-sourced, should be same as 2
$sent array iff ajax-sourced
[passwd] => "passnow"
[passwd2] => "someother" new, should be different
*/

$lvl = $cdata['security_level'];
switch ($lvl) {
 case Auther::NOBOT:
	//nothing to do
	break;
 case Auther::LOSEC:
 case Auther::MIDSEC:
 case Auther::CHALLENGED:
	$flds = [];
	//common stuff
	$login = trim($_POST[$id.'login']);
	if (!$login) {
		$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
		$focus = 'login';
	}
	$t = ($jax) ? $sent['passwd'] : $_POST[$id.'passwd'];
	$pw = trim($t);
	if (!$pw) {
		$msgs[] = $mod->Lang('missing_type', $mod->Lang('password'));
		if (!$focus) { $focus = 'passwd'; }
	} elseif ($login) {
		$res = $afuncs->isRegistered($login, $pw);
		$fake = !$res[0];
		$sdata = $res[1];
		if (!$res[0]) {
			$n = $cdata['attempts_before_ban'];
			if ($sdata['attempts'] >= $n) {
//TODO status 'blocked'
				$vfuncs->SetForced(1, FALSE, $login, $cdata['id']);
				$forcereset = TRUE;
				$msgs[] = $mod->Lang('reregister2');
			} else {
				$n = $cdata['attempts_before_action'];
				if ($sdata['attempts'] >= $n) {
					$msgs[] = $mod->Lang('reregister');
// SILENT		} else {
//					$msgs[] = $mod->Lang('invalid_type', $this->mod->Lang('title_login'));
				}
				$focus = 'login';
			}
		}
	}

	$t = ($jax) ? $sent['passwd2'] : $_POST[$id.'passwd2'];
	$pw2 = trim($t);
	if ($pw === $pw2) {
		$msgs[] = $mod->Lang('newpassword_match');
		if (!$focus) { $focus = 'passwd2'; }
	}
	$res = $afuncs->validatePassword($pw2);
	if ($res[0]) {
		$flds['privhash'] = $pw2; //hash when required
	} else {
		$msgs[] = $res[1];
		if (!$focus) { $focus = 'passwd2'; }
	}
	if (!$jax) { //i.e. passwords not matched in browser
		if ($pw2 !== trim($_POST[$id.'passwd3'])) {
			unset($flds['privhash']);
			$msgs[] = $mod->Lang('newpassword_nomatch');
			if (!$focus) { $focus = 'passwd2'; }
		}
	}

	switch ($lvl) {
	 case Auther::MIDSEC:
	//check stuff
		if (!$jax) {
			if ($params['captcha'] !== $_POST[$id.'captcha']) {
				$msgs[] = $mod->Lang('err_captcha');
				if (!$focus) { $focus = 'captcha'; }
			}
		}
		break;
	 case Auther::CHALLENGED:
	//check stuff
		if (!$jax) {
		}
		break;
	} //switch $lvl
	break;
 case Auther::HISEC:
 //TODO
	break;
} //switch $lvl

if ($msgs || $fake) {
	$afuncs->AddAttempt();
} else {
	if ($lvl == Auther::CHALLENGED) {
		$flds['login'] = $login;
		$flds['passwd'] = $pw; //original value
		$enc = $cfuncs->encrypt_value($mod, json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$uid = $afuncs->getUserID($login);
		$afuncs->changePassword($uid, $pw, $pw2, $pw2);
		$afuncs->ResetAttempts();
		$vfuncs->SetForced(0, $uid);
	}
}
