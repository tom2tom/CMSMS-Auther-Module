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
[pA762_login2]	"somethingorempty"
[pA762_recover]	"0" OR "1" if 1, only login value is relevant
[pA762_name]	"whateverorempty"
[pA762_contact]	"whateverorempty"
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
		'login2',
		'passwd',
		'name',
		'contact',
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
		} elseif ($login) { //ok, already fail if no login
			$res = $afuncs->IsRegistered($login, $pw);
			$fake = !$res[0];
			$sdata = $res[1];
			if ($res[0]) {
				if ($vfuncs->IsForced(FALSE, $login, $cdata['id'])) {
					$forcereset = TRUE;
					break;
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
		}
	} else {
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
		if (!$focus) { $focus = 'passwd'; }
	}

	$pass1 = $_POST[$id.'phase'] == 'who';
	if ($pass1) {
		break;
	}

	$t = $postvars[$id.'login2'];
	if ($vfuncs->FilteredString($t)) {
		$t = trim($t);
		if ($t) {
			$res = $afuncs->ValidateLogin($t);
			if ($res[0]) {
				if (0) { //TODO extra test criterion
					$res = $afuncs->SensibleLogin($t);
				}
			}
			if ($res[0]) {
				$res = $afuncs->UniqueLogin($t, $login);
				if ($res[0]) {
					$flds['publicid'] = $t;
				} else {
					$msgs[] = $mod->Lang('retry'); //NOT the default 'invalid' message!
					$focus = 'login2';
				}
			} else {
				$msgs[] = $res[1];
				if (!$focus) { $focus = 'login2'; }
			}
		}
	} else {
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('title_login')); //TODO 'replacement' into message
		if (!$focus) { $focus = 'login2'; }
	}

	$t = $postvars[$id.'name'];
	if ($vfuncs->FilteredString($t)) {
		$t = $vfuncs->SanitizeName($t);
		$res = $afuncs->ValidateName($t);
		if ($res[0]) {
			if (0) { //TODO extra test criterion
				$res = $afuncs->SensibleName($t);
			}
		}
		if ($res[0]) {
			$flds['name'] = $t; //crypt if/when needed
		} else {
			$msgs[] = $res[1];
			if (!$focus) { $focus = 'name'; }
		}
	} else {
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('name'));
		if (!$focus) { $focus = 'name'; }
	}

	$t = $postvars[$id.'contact'];
	if ($vfuncs->FilteredString($t)) {
		$t = trim($t);
		if ($t) {
			$res = $afuncs->ValidateAddress($t);
			if ($res[0]) {
				$flds['address'] = $t; //crypt if/when needed
			} else {
				$msgs[] = $res[1];
				if (!$focus) { $focus = 'contact'; }
			}
		}
	} else {
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('title_contact'));
		if (!$focus) { $focus = 'contact'; }
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
		$namers = [];
		$args[] = [];
		foreach ($flds as $field=>$val) {
			$namers[] = $field.'=?';
			switch ($field) {
			 case 'publicid':
				$args[] = $val;
			 case 'name':
			 case 'address':
			 	$args[] = $cfuncs->encrypt_value($mod, $val);
			}
		}
		$fillers = implode(',',$namers);
		$sql = 'UPDATE '.$pref.'module_auth_users SET '.$fillers.' WHERE id=?';
		$args[] = $afuncs->GetUserID($login);
		$db->Execute($sql, [$args]);

		$afuncs->ResetAttempts();
	}
}
