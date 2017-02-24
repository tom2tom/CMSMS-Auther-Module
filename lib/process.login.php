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

$postvars = [];
foreach ([
	'login',
	'passwd',
	'captcha'
] as $t) {
	$key = $id.$t;
	$postvars[$key] = isset($_POST[$key]) ? $_POST[$key] : NULL;
}

$lvl = $cdata['security_level'];
switch ($lvl) {
 case Auther::NOBOT:
	if ($jax) {
	//check Google via API?
		if (0) {
			$msgs[] = $mod->Lang('invalid_type', 'CAPTCHA');
			$focus = 'TODO';
		}
	} else {
		$key = $id.'captcha';
		$t = $vfuncs->FilteredPassword($postvars[$key]);
		if (!$t) {
			$msgs[] = $mod->Lang('missing_type', 'CAPTCHA');
			$focus = 'captcha';
		} elseif ($t != $_POST[$key] || $t != $params['captcha']) {
			$msgs[] = $mod->Lang('err_captcha');
			$focus = 'captcha';
		}
	}
	break;
 case Auther::LOSEC:
 case Auther::MIDSEC:
 case Auther::CHALLENGED:
	//common stuff
	$key = $id.'login';
	$t = $vfuncs->FilteredString($postvars[$key]);
	if (isset($_POST[$key]) && $_POST[$key] != $t) {
		$login = FALSE;
		$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('invalid_type', $mod->Lang($t));
		$focus = 'login';
	} else {
		$login = trim($t);
		if (!$login) {
			$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
			$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
			$focus = 'login';
		}
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
			$msgs[] = $mod->Lang('invalid_type', $mod->Lang('password'));
			if (!$focus) { $focus = 'passwd'; }
		}
	}
	$pw = trim($t);
	if (!$pw) {
		$msgs[] = $mod->Lang('missing_type', $mod->Lang('password'));
		if (!$focus) { $focus = 'passwd'; }
	} elseif ($login) {
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
} //switch level

if ($msgs || $fake) {
	$afuncs->AddAttempt();
} else {
	if ($lvl == Auther::CHALLENGED) {
		$flds = ['login' => $login, 'passwd' => $pw];
		$enc = $cfuncs->encrypt_value($mod, json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$afuncs->Login($login, $pw, TRUE);
		$afuncs->ResetAttempts();
	}
}
