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
	$t = ($jax) ? $sent['passwd'] : $_POST[$id.'passwd'];
	$pw = trim($t);
	$res = $vfuncs->IsKnown($login, $pw);
	if ($res[0]) {
//TODO handle force-reset flag for user
	} else {
		$msgs[] = $res[1];
		$focus = 'login';
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
	}

	if (!$msgs) {
		$t = trim($_POST[$id.'login']);
		if ($lvl == Auther\Setup::CHALLENGED) {
			//cache $login, provided data (from $flds[])
			$data = json_encode($TODO);
			$enc = $cfuncs->encrypt_value($mod, $data);
			$sql = 'UPDATE '.$pref.'module_auth_sessions SET cache=? WHERE token=?';
			$db->Execute($sql, [$enc, $token]);
			//TODO initiate challenge
		} else {
			$afuncs->login($t, $pw, FALSE, TRUE);
		}
	}
	break;
 case Auther\Setup::HISEC:
 //TODO
	break;
}
