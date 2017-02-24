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
1st pass:
various empty inputs
2nd pass:
[pA762_passwd]	"token" iff NOT ajax-sourced
[pA762_passwd2]	"someother" iff NOT ajax-sourced, should not be same as 1
[pA762_passwd3]	"someother" iff NOT ajax-sourced, should be same as 2
$sent array iff ajax-sourced
[passwd] => "token"
[passwd2] => "someother"
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
 		'passwd2',
 		'passwd3',
 		'captcha'
	] as $t) {
		$key = $id.$t;
		$postvars[$key] = isset($_POST[$key]) ? $_POST[$key] : NULL;
	}
	$flds = [];
	$key = $id.'login';
	$t = $vfuncs->FilteredString($postvars[$key]);
	if (isset($_POST[$key]) && $_POST[$key] != $t) {
		$login = FALSE;
		$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang($t));
		$focus = 'login';
	} else {
		$login = trim($t);
	}

	if ($login) {
		$res = $afuncs->IsRegistered($login);
		$fake = !$res[0];
		$sdata = $res[1];
		if ($res[0]) {
			$res = $vfuncs->IsTellable($login, 'temp_notsent');
			if ($res[0]) {
				if (!$pass1) {
					$token = $sdata['token'];
				}
			} else {
				$msgs[] = $res[1];
				$focus = 'login';
			}
		} else {
			$n = $cdata['ban_count'];
			if ($sdata['attempts'] >= $n) {
//TODO status 'blocked'
				$vfuncs->SetForced(1, FALSE, $login, $cdata['id']);
				$forcereset = TRUE;
				$msgs[] = $mod->Lang('reregister2');
			} else {
				$n = $cdata['raise_count'];
				if ($sdata['attempts'] >= $n) {
					$msgs[] = $mod->Lang('reregister');
// SILENT		} else {
//					$msgs[] = $mod->Lang('invalid_type', $mod->Lang('title_login'));
				}
				$focus = 'login';
			}
		}
	} else {
		$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
		$focus = 'login';
	}

	$pass1 = $_POST[$id.'phase'] == 'who';
	if ($pass1) {
		break;
	}

	if ($jax) {
		$t = $vfuncs->FilteredPassword($sent['passwd']);
		if ($sent['passwd'] != $t) {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd'; }
		}
	} else {
		$key = $id.'passwd';
		$t = $vfuncs->FilteredPassword($postvars[$key]);
		if (isset($_POST[$key]) && $_POST[$key] != $t) {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('token_temp'));
			if (!$focus) { $focus = 'passwd'; }
		}
	}
	$pw = trim($t);
	$data = json_decode($sdata['cache']);
	if (!$afuncs->DoPasswordCheck($pw, $data['token'], $sdata['attempts'])) {
		$msgs[] = $mod->Lang('incorrect_resetkey');
		break;
	}

	if ($jax) {
		$t = $vfuncs->FilteredPassword($sent['passwd2']);
		if ($sent['passwd2'] != $t) {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd2'; }
		}
	} else {
		$key = $id.'passwd2';
		$t = $vfuncs->FilteredPassword($postvars[$key]);
		if (isset($_POST[$key]) && $_POST[$key] != $t) {
			$pw2 = NULL;
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd2'; }
		}
	}
	$pw2 = trim($t);
	$res = $afuncs->ValidatePassword($pw2);
	if ($res[0]) {
		if (!$msgs) {
			$flds['privhash'] = $pw2; //hash when required
		}
	} else {
		$msgs[] = $res[1];
		if (!$focus) { $focus = 'passwd2'; }
	}

	if (!$jax) { //i.e. passwords not matched in browser
		$key = $id.'passwd3';
		$t = $vfuncs->FilteredPassword($postvars[$key]);
		if (isset($_POST[$key]) && $_POST[$key] != $t) {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd2'; }
		}
		if ($pw2 !== trim($t)) {
			unset($flds['privhash']);
			$msgs[] = $mod->Lang('newpassword_nomatch');
			if (!$focus) { $focus = 'passwd2'; }
		}
	}

	switch ($lvl) {
	 case Auther::MIDSEC:
	//check stuff
		if (!$jax) {
			$key = $id.'captcha';
			$t = $vfuncs->FilteredPassword($postvars[$key]);
			if (!$t) {
				$msgs[] = $mod->Lang('missing_type', 'CAPTCHA');
				if (!$focus) { $focus = 'captcha'; }
			} elseif ($t != $_POST[$key] || $t != $params['captcha']) {
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
} elseif ($pass1) {
	if ($lvl == Auther::CHALLENGED) {
		$pw = $afuncs->UniqueToken($afuncs->GetConfig('password_min_length'));
		$hash = password_hash($pw, PASSWORD_DEFAULT);
		$data = json_encode(['token'=>$hash]);
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$data, $token]);
		$res = $afuncs->RequestReset($login, NULL, $pw); //TODO wrong class etc BAD
		if (!$res[0]) {
			$msgs[] = $res[1];
		} elseif (!$sendmail) {
			$msgs[] = $mod->Lang('TODO');
		}
		if (!$msgs) {
			$t = ['focus'=>'authfeedback', 'html'=>$mod->Lang('temp_sent')];
			if ($jax) {
				header('HTTP/1.1 200 OK');
				header('Content-Type: application/json; charset=UTF-8');
				die(json_encode($t));
			} else {
				notify_handler($params, $t);
				exit;
			}
		}
	} else {
		$t = ['focus'=>'authfeedback', 'html'=>'TODO message'];
		if ($jax) {
			header('HTTP/1.1 200 OK');
			header('Content-Type: application/json; charset=UTF-8');
			die(json_encode($t));
		} else {
			notify_handler($params, $t);
			exit;
		}
	}
} else {
	if ($lvl == Auther::CHALLENGED) {
		$flds['login'] = $login; //original value
		$flds['passwd'] = $pw;
		$enc = $cfuncs->encrypt_value($mod, json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$uid = $afuncs->GetUserID($login);
		$afuncs->ChangePassword($uid,$pw,$pw2,$pw2,FALSE); //TODO no check?
		$afuncs->ResetAttempts();
		$vfuncs->SetForced(0, FALSE, $login, $sdata['id']);
	}
}
