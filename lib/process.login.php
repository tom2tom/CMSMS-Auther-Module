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
 case Auther\Setup::NOBOT:
	if ($jax) {
	//check Google via API?
		if (0) {
			$msgs[] = $mod->Lang('invalid_type', 'CAPTCHA');
			$focus = 'TODO';
		}
	} else {
		$t = $_POST[$id.'captcha'];
		if (!$t) {
			$msgs[] = $mod->Lang('missing_type', 'CAPTCHA');
			$focus = 'captcha';
		} elseif ($t !== $params['captcha']) {
			$msgs[] = $mod->Lang('err_captcha');
			$focus = 'captcha';
		}
	}
	break;
 case Auther\Setup::LOSEC:
 case Auther\Setup::NONCED:
 case Auther\Setup::CHALLENGED:
	//common stuff
	$login = trim($_POST[$id.'login']);
	if (!$login) {
		$t = ($cdata['email_required']) ? 'title_email':'title_identifier';
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
		if ($res[0]) {
			if ($vfuncs->IsForced(FALSE, $login, $cdata['id'])) {
				$forcereset = TRUE;
				break;
			}
		} else {
			$n = $afuncs->GetConfig('attempts_before_ban');
			if ($sdata['attempts'] >= $n) {
//TODO status 'blocked'
				$vfuncs->SetForced(1, FALSE, $login, $cdata['id']);
				$forcereset = TRUE;
				$msgs[] = $mod->Lang('reregister2');
			} else {
				$n = $afuncs->GetConfig('attempts_before_action');
				if ($sdata['attempts'] >= $n) {
					$msgs[] = $mod->Lang('reregister');
// SILENT		} else {
//					$msgs[] = $mod->Lang('login_notvalid');
				}
				$focus = 'login';
			}
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
	} //switch $lvl
	break;
 case Auther\Setup::HISEC:
 //TODO
	break;
} //switch $lvl

if ($msgs || $fake) {
	$afuncs->AddAttempt();
} else {
	if ($lvl == Auther\Setup::CHALLENGED) {
		$flds = ['login' => $login, 'passwd' => $pw];
		$enc = $cfuncs->encrypt_value($mod, json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$afuncs->login($login, $pw, FALSE, TRUE);
		$afuncs->ResetAttempts();
	}
}
