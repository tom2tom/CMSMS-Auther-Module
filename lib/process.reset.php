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
	$postvars = collect_post($id, [
		'login',
		'passwd',
		'passwd2',
		'passwd3',
		'captcha'
	]);
	$phase1 = empty($_POST[$id.'phase']) || $_POST[$id.'phase'] == 'who';
	$flds = [];
	$t = $postvars['login'];
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

	$t = ($jax) ? $sent['passwd'] : $postvars['passwd'];
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

	if ($phase1) {
		break;
	}

	$t = ($jax) ? $sent['passwd2'] : $postvars['passwd2'];
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
					$flds['passhash'] = $pw2; //hash when required
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
		$t = $postvars['passwd3'];
		if ($vfuncs->FilteredPassword($t)) {
			if ($pw2 !== trim($t)) {
				unset($flds['passhash']);
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
			$t = $postvars['captcha'];
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
} elseif ($phase1) {
	$afuncs->ResetAttempts();
	if ($lvl == Auther::CHALLENGED) {
//TODO
	} else {
		$t = ['focus' => 'passwd'];
		if ($jax) {
			header('HTTP/1.1 200 OK');
			header('Content-Type: application/json; charset=UTF-8');
			die(json_encode($t));
		} else {
			$others = ['authdata' => base64_encode(json_encode((object)$t))];
			notify_handler($params, $others);
			exit;
		}
	}
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
		$res = $afuncs->ChangePasswordReal($uid, $pw2);
		if ($res[0]) {
		//TODO CHECK clear cached session ? what if login duration ?
//			$sql = 'DELETE FROM '.$pref.'module_auth_cache WHERE token=?';
			$sql = 'UPDATE '.$pref.'module_auth_cache SET attempts=0,data=NULL WHERE token=?';
			$db->Execute($sql, [$token]);
//			$afuncs->ResetAttempts();
			$vfuncs->SetForced(0, FALSE, $login, $cdata['id']);
			$forcereset = FALSE;
			$msgtext = $mod->Lang('password_changed'); //feedback
		} else {
			$msgs[] = $res[1];
		}
	}
}
