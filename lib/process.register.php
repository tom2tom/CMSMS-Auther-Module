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
[pA762_passwd]	"passnew" iff NOT ajax-sourced
[pA762_passwd2]	"passnew" iff NOT ajax-sourced, should be same as 1
[pA762_name]	"whatever"
[pA762_contact]	"whatever"
$sent array iff ajax-sourced
[passwd] => "text"
[passwd2] => "text" should match
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
		if ($login) {
			$res = $afuncs->ValidateLogin($login);
			if ($res[0]) {
				if (0) { //TODO extra test criterion
					$res = $afuncs->SensibleLogin($login);
				}
			}
			if ($res[0]) {
				$res = $afuncs->UniqueLogin($login);
				if ($res[0]) {
					$flds['publicid'] = $login;
				} else {
					$msgs[] = $mod->Lang('retry'); //NOT the default 'invalid' message!
					$focus = 'login';
				}
			} else {
				$msgs[] = $res[1];
				$focus = 'login';
			}
		} else {
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
		if ($pw) {
			$res = $afuncs->ValidatePassword($pw);
			if ($res[0]) {
				if (!$msgs) {
					$flds['privhash'] = $pw; //hash when required
				}
			} else {
				$msgs[] = $res[1];
				if (!$focus) { $focus = 'passwd'; }
			}
		} else {
			$msgs[] = $mod->Lang('missing_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd'; }
		}
	} else {
		$pw = FALSE;
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
		if (!$focus) { $focus = 'passwd'; }
	}

	if (!$jax) { //i.e. passwords not matched in browser
		$t = $postvars[$id.'passwd2'];
		if ($vfuncs->FilteredPassword($t)) {
			if ($pw !== trim($t)) {
				unset($flds['privhash']);
				$msgs[] = $mod->Lang('newpassword_nomatch'); //TODO not new
				if (!$focus) { $focus = 'passwd2'; }
			}
		} else {
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd2'; }
		}
	}

	$t = $postvars[$id.'name'];
	if ($vfuncs->FilteredString($t)) {
		$t = $vfuncs->SanitizeName($t);
		if ($t) {
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
		} elseif ($cdata['name_required']) {
			$msgs[] = $mod->Lang('missing_type', $mod->Lang('name'));
			if (!$focus) { $focus = 'name'; }
		} else {
			$flds['name'] = '';
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
		} elseif ($cdata['address_required']) {
			$msgs[] = $mod->Lang('missing_type', $mod->Lang('title_contact'));
			if (!$focus) { $focus = 'contact'; }
		} else {
			$flds['address'] = '';
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

if (!$msgs) {
	if ($lvl == Auther::CHALLENGED) {
		$enc = $cfuncs->encrypt_value($mod, json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$res = $afuncs->AddUser($flds['publicid'], $pw, $flds['name'], $flds['address'], []);  //TODO $check?
		if ($res[0]) {
			$uidnew = $res[1]; //for use by includer
			$afuncs->ResetAttempts();
		} else {
			$msgs[] = $res[1];
//TODO		$afuncs->AddAttempt();
		}
	}
}
