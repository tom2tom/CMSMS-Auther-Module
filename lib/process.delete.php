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
[pA762_recover]	"0" OR "1" if 1, only login value is relevant
$sent array iff ajax-sourced
[passwd] => "passnow"
*/

$lvl = $cdata['security_level'];
switch ($lvl) {
 case Auther::NOBOT:
	//nothing to do
	break;
 case Auther::LOSEC:
 case Auther::MIDSEC:
 case Auther::CHALLENGED:
	//common stuff
	$postvars = [];
	foreach ([
		'login',
		'passwd',
		'captcha'
	] as $t) {
		$key = $id.$t;
		$postvars[$key] = isset($_POST[$key]) ? $_POST[$key] : NULL;
	}
	$t = $postvars[$id.'login'];
	if ($vfuncs->FilteredString($t)) {
		$login = trim($t);
		if (!$login) {
			$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
			$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
			$focus = 'login';
		}
	} else {
		$login = FALSE;
		$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang($t));
		$focus = 'login';
	}

	$t = ($jax) ? $sent['passwd'] : $postvars[$id.'passwd'];
	if ($vfuncs->FilteredPassword($t)) {
		$pw = trim($t);
		if (!$pw) {
			$msgs[] = $mod->Lang('missing_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd'; }
		} elseif ($login) { //ok, we already fail if no login
			$res = $afuncs->IsRegistered($login, $pw);
			if (!$res[0]) {
				$msgs[] = $res[1];
				$focus = 'login';
			}
		}
	} else {
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
		if (!$focus) { $focus = 'passwd'; }
	}

	switch ($lvl) {
	 case Auther::MIDSEC:
	//check stuff
		if (!$jax) {
			$t = $postvars[$id.'captcha'];
			if ($vfuncs->FilteredPassword($t)) {
				if (!$t) {
					$msgs[] = $mod->Lang('missing_type', 'CAPTCHA');
					if (!$focus) { $focus = 'captcha'; }
				} elseif ($t != $params['captcha']) {
					$msgs[] = $mod->Lang('err_captcha');
					if (!$focus) { $focus = 'captcha'; }
				}
			} else {
				$msgs[] = $mod->Lang('invalid_type', 'CAPTCHA');
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
} //switch level

if ($msgs) {
	$afuncs->AddAttempt();
} else {
	if ($lvl == Auther::CHALLENGED) {
		$flds = ['login' => $login, 'passwd' => $pw];
		$enc = $cfuncs->encrypt_value($mod, json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$res = $afuncs->DeleteUser($login, $pw);
		if (!$res[0]) {
			$msgs[] = $rest[1];
		}
	}
}
