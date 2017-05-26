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
1st pass:
various empty inputs
2nd pass:
[pA762_login2]	"somethingorempty"
[pA762_name]	"whateverorempty"
[pA762_contact]	"whateverorempty"
$sent array iff ajax-sourced
[passwd] => "passnow"
[passwd2] => "newpass" iff replacement is present
[passwd3] => "newpass" should match
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
		'login2',
		'passwd',
		'passwd2', //present if !$jax, or no replacement password provided
		'passwd3', //ditto
		'name',
		'contact',
		'captcha'
	]);
	$phase1 = empty($_POST[$id.'phase']) || $_POST[$id.'phase'] == 'who';
	$mfuncs = new Auther\Challenge($mod, $params['context']);
	$sendto = FALSE;
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
		} elseif ($login) { //ok, already fail if no login
			$res = $afuncs->IsRegistered($login, $pw, TRUE, FALSE, $params['token']);
			if ($res[0]) {
				$fake = FALSE;
				if ($vfuncs->IsForced(FALSE, $login, $cdata['id'])) {
					$forcereset = TRUE;
					//TODO what is reset-token $sdata['token']? any message?
					break;
				}
			} else {
				$fake = TRUE;
				$n = $cdata['ban_count'];
				$sdata = $res[1];
				if ($sdata['attempts'] >= $n) {
					//TODO status 'blocked'
					$vfuncs->SetForced(1, FALSE, $login, $cdata['id']);
					$forcereset = TRUE;
					//TODO what is reset-token $sdata['token']? any message?
					$msgs[] = $mod->Lang('reregister2');
				} else {
					$n = $cdata['raise_count'];
					if ($sdata['attempts'] >= $n) {
						$msgs[] = $mod->Lang('reregister');
					} else {
						$msgs[] = $mod->Lang('incorrect_vague'); //CHECKME no need for fake/silence here?
					}
					$focus = 'login';
				}
			}
		}
	} else {
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
		if (!$focus) {
			$focus = 'passwd';
		}
	}

	if ($phase1) {
		break;
	}

	$t = $postvars['login2'];
	if ($t) {
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
						if (!$cdata['email_login']) {
							$alt = $afuncs->NumberedLogin($login);
							if ($alt) {
								$msgs[] = $mod->Lang('login_taken2', $login, $alt);
							} else {
								$msgs[] = $mod->Lang('retry'); //NOT the default 'invalid' message!
							}
						} else {
							$msgs[] = $mod->Lang('retry'); //NOT the default 'invalid' message!
						}
						if (!$focus) {
							$focus = 'login2';
						}
					}
				} else {
					$msgs[] = $res[1];
					if (!$focus) {
						$focus = 'login2';
					}
				}
			}
		} else {
			$t = ($cdata['email_login']) ? 'title_email' : 'title_identifier'; //TODO 'replacement' into message
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang($t));
			if (!$focus) {
				$focus = 'login2';
			}
		}
//	} else { //no replacement login
	}

	if ($jax && !empty($sent['passwd2'])) {
		$t = $sent['passwd2'];
	} else {
		$t = $postvars['passwd2'];
	}
	if ($t) {
		if ($vfuncs->FilteredString($t)) {
			$res = $afuncs->ValidatePassword($t);
			if ($res[0]) {
				$flds['privhash'] = $t; //crypt later
			} else {
				$msgs[] = $res[1];
				if (!$focus) {
					$focus = 'passwd2';
				}
			}
		} else {
			//invalid
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password')); //TODO 'replacement' into message
			if (!$focus) {
				$focus = 'passwd2';
			}
		}
//	} else { //no replacement password
	}

	if (!empty($flds['privhash'])) {
		if ($jax && !empty($sent['passwd3'])) {
			$t = $sent['passwd3'];
		} else {
			$t = $postvars['passwd3'];
		}
		if ($t != $flds['privhash']) {
			unset($flds['privhash']);
			$msgs[] = $mod->Lang('newpassword_nomatch');
		}
	}

	$t = $postvars['name'];
	if ($t) {
		if ($vfuncs->FilteredString($t)) {
			$t = $vfuncs->SanitizeName($t);
			$res = $afuncs->ValidateName($t);
			if ($res[0]) {
				if (0) { //TODO extra test criterion
					$res = $afuncs->SensibleName($t);
				}
			}
			if ($res[0]) {
				$flds['name'] = $t; //crypt later
			} else {
				$msgs[] = $res[1];
				if (!$focus) {
					$focus = 'name';
				}
			}
		} else {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('name'));
			if (!$focus) {
				$focus = 'name';
			}
		}
//	} else { //no replacement name
	}

	$t = $postvars['contact'];
	if ($t) {
		if ($vfuncs->FilteredString($t)) {
			$t = trim($t);
			if ($t) {
				$res = $afuncs->ValidateAddress($t);
				if ($res[0]) {
					$flds['address'] = $t; //crypt later
				} else {
					$msgs[] = $res[1];
					if (!$focus) {
						$focus = 'contact';
					}
				}
			}
		} else {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('title_contact'));
			if (!$focus) {
				$focus = 'contact';
			}
		}
//	} else { //no replacment contact
	}

	if ($cdata['email_required']) {
		/*TODO check current & new
		if (!(preg_match(Auth::PATNEMAIL, $login) || preg_match(Auth::PATNEMAIL, $contact))) {
			$msgs[] = $mod->Lang('want_email');
			if (!$focus) { $focus = 'contact'; }
		}
*/
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
	$pw = $mfuncs->SimpleToken(8);
	if ($lvl == Auther::CHALLENGED) {
		if ($sendto) {
			$res = $mfuncs->TellUser($sendto, 'change', $pw);
			if ($res[0]) {
				$hash = password_hash($pw, PASSWORD_DEFAULT);
				$data = json_encode(['temptoken' => $hash]);
				$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
				$db->Execute($sql, [$data, $token]);
			} else {
				$msgs[] = $res[1];
			}
		} else {
			$msgs[] = $mod->Lang('not_contactable');
		}
		if (!$msgs) {
			$t = ['focus' => 'authfeedback', 'html' => $mod->Lang('temp_sent')];
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
		$t = ['focus' => 'login2', 'html' => $pw];
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
		$flds['login'] = $login; //original value
		$flds['passwd'] = $pw;
		$enc = $cfuncs->encrypt_value(json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$namers = [];
		$args = [];
		foreach ($flds as $field => $val) {
			$namers[] = $field.'=?';
			switch ($field) {
			 case 'publicid':
				$args[] = $val;
				break;
			 case 'privhash':
				$args[] = password_hash($val, PASSWORD_DEFAULT);
				break;
			 case 'name':
			 case 'address':
				$args[] = $cfuncs->encrypt_value($val);
				break;
			}
		}
		$fillers = implode(',', $namers);
		$sql = 'UPDATE '.$pref.'module_auth_users SET '.$fillers.' WHERE id=?';
		$args[] = $afuncs->GetUserID($login);
		$db->Execute($sql, [$args]);

		if (isset($flds['privhash'])) {
			$vfuncs->SetForced(0, FALSE, $login, $sdata['id']);
			$forcereset = FALSE;
		}
		$afuncs->ResetAttempts();
		$msgtext = $mod->Lang('change_success'); //feedback
	}
}
