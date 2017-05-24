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
	$t = $postvars[$id.'login'];
	if ($vfuncs->FilteredString($t)) {
		$login = trim($t);
		if (!$login) {
			$t = ($cdata['email_login']) ? 'title_email' : 'title_identifier';
			$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
			$focus = 'login';
		}
	} else {
		$login = FALSE;
		$t = ($cdata['email_login']) ? 'title_email' : 'title_identifier';
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang($t));
		$focus = 'login';
	}

	$t = ($jax) ? $sent['passwd'] : $postvars[$id.'passwd'];
	if ($vfuncs->FilteredPassword($t)) {
		$pw = trim($t);
		if (!$pw) {
			$msgs[] = $mod->Lang('missing_type', $mod->Lang('password'));
			if (!$focus) {
				$focus = 'passwd';
			}
		} elseif ($login) {
			$res = $afuncs->IsRegistered($login, $pw, TRUE, FALSE, $params['token']);
			$fake = !$res[0];
			if (!$res[0]) {
				$n = $cdata['ban_count'];
				$sdata = $res[1];
				if ($sdata['attempts'] >= $n) {
					//TODO status 'blocked'
					$vfuncs->SetForced(1, FALSE, $login, $cdata['id']);
					$forcereset = TRUE; //CHECKME sensible during this (maybe voluntary) reset?
					//TODO what is reset-token $sdata['token']?
					$msgs[] = $mod->Lang('reregister2');
				} else {
					$n = $cdata['raise_count'];
					if ($sdata['attempts'] >= $n) {
						$msgs[] = $mod->Lang('reregister');
// SILENT			} else {
//						$msgs[] = $mod->Lang('invalid_type', $mod->Lang('title_login'));
					}
					$focus = 'login';
				}
			}
		}
	} else {
		$pw = FALSE;
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
		if (!$focus) {
			$focus = 'passwd';
		}
	}

	$t = ($jax) ? $sent['passwd2'] : $postvars[$id.'passwd2'];
	if ($vfuncs->FilteredPassword($t)) {
		$pw2 = trim($t);
		if ($pw === $pw2) {
			$msgs[] = $mod->Lang('newpassword_match');
			if (!$focus) {
				$focus = 'passwd2';
			}
		} elseif ($pw2) {
			$res = $afuncs->ValidatePassword($pw);
			if ($res[0]) {
				if (!$msgs) {
					$flds['privhash'] = $pw2; //hash when required
				}
			} else {
				$msgs[] = $res[1];
				if (!$focus) {
					$focus = 'passwd2';
				}
			}
		} else {
			$msgs[] = $mod->Lang('missing_type', $mod->Lang('password'));
			if (!$focus) {
				$focus = 'passwd2';
			}
		}
	} else {
		$pw2 = FALSE;
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
		if (!$focus) {
			$focus = 'passwd2';
		}
	}

	if (!$jax) { //i.e. passwords not matched in browser
		$t = $postvars[$id.'passwd3'];
		if ($vfuncs->FilteredPassword($t)) {
			if ($pw2 !== trim($t)) {
				unset($flds['privhash']);
				$msgs[] = $mod->Lang('newpassword_nomatch');
				if (!$focus) {
					$focus = 'passwd2';
				}
			}
		} else {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
			if (!$focus) {
				$focus = 'passwd2';
			}
		}
	}

	switch ($lvl) {
	 case Auther::MIDSEC:
	//check stuff
		if (!$jax) {
			$t = $postvars[$id.'captcha'];
			if ($vfuncs->FilteredPassword($t)) {
				if (!$t) {
					$msgs[] = $mod->Lang('missing_type', 'CAPTCHA');
					if (!$focus) {
						$focus = 'captcha';
					}
				} elseif ($t != $params['captcha']) {
					$msgs[] = $mod->Lang('err_captcha');
					if (!$focus) {
						$focus = 'captcha';
					}
				}
			} else {
				$msgs[] = $mod->Lang('invalid_type', 'CAPTCHA');
				if (!$focus) {
					$focus = 'captcha';
				}
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

if ($msgs || $fake) {
	$afuncs->AddAttempt($params['token']);
} else {
	if ($lvl == Auther::CHALLENGED) {
		$flds['login'] = $login;
		$flds['passwd'] = $pw; //original value
		$enc = $cfuncs->encrypt_value(json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$uid = $afuncs->GetUserID($login);
		$afuncs->ChangePassword($uid, $pw, $pw2, $pw2); //TODO $check?
		$afuncs->ResetAttempts();
		$vfuncs->SetForced(0, $uid);
		$msgtext = $mod->Lang('password_changed'); //feedback
	}
}
