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

$lvl = $cdata['security_level'];
switch ($lvl) {
 case Auther\Setup::NOBOT:
	//nothing to do
	break;
 case Auther\Setup::LOSEC:
 case Auther\Setup::NONCED:
 case Auther\Setup::CHALLENGED:
	$flds = [];
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

	$t = trim($_POST[$id.'login2']);
	if ($t) {
		$res = $afuncs->validateLogin($t);
		if ($res[0]) {
			if (0) { //TODO extra test criterion
				$res = $afuncs->sensibleLogin($t);
			}
		}
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
		$t = $vfuncs->SanitizeName($t);
		$res = $afuncs->validateName($t);
		if ($res[0]) {
			if (0) { //TODO extra test criterion
				$res = $afuncs->sensibleName($t);
			}
		}
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
		$args[] = $afuncs->getUserID($login);
		$db->Execute($sql, [$args]);

		$afuncs->ResetAttempts();
	}
}
