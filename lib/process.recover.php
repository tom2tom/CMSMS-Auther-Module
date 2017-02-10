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
1st pass:
various empty inputs
2nd pass:
[pA762_passwd]	"temppass" iff NOT ajax-sourced
[pA762_passwd2]	"someother" iff NOT ajax-sourced, should not be same as 1
[pA762_passwd3]	"someother" iff NOT ajax-sourced, should be same as 2
$sent array iff ajax-sourced
[passwd] => "temppass"
[passwd2] => "someother" new
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
	$pass1 = $_POST[$id.'phase'] == 'who'; //might otherwisse be 'pass'
	//common stuff
	$login = trim($_POST[$id.'login']);
	if ($login) {
		$res = $afuncs->isRegistered($login, FALSE);
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
//		} else { ignore if unkown, to hinder forcers
//			$msgs[] = $mod->Lang('login_notvalid');
//			$focus = 'login';
		}
	} else {
		$t = ($cdata['email_required']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
		$focus = 'login';
	}
	if ($pass1) {
		break;
	}

	$pw = ($jax) ? $sent['passwd'] : trim($_POST[$id.'passwd']);
	$data = json_decode($sdata['cache']);
	if (!$afuncs->doPasswordCheck($pw, $data['temppass'], $sdata['attempts'])) {
		$afuncs->AddAttempt();
		$msgs[] = $mod->Lang('password_incorrect'); //TODO 'temporary' qualifier
		break;
	}

	$t = ($jax) ? $sent['passwd2'] : $_POST[$id.'passwd2'];
	$pw2 = trim($t);
	$res = $afuncs->validatePassword($pw2);
	if ($res[0]) {
		$flds['privhash'] = $pw2; //hash when required
	} else {
		$msgs[] = $res[1];
		if (!$focus) { $focus = 'passwd2'; }
	}
	if (!$jax) { //i.e. passwords not matched in browser
		if ($pw2 !== trim($_POST[$id.'passwd3'])) {
			unset($flds['privhash']);
			$msgs[] = $mod->Lang('newpassword_nomatch');
			if (!$focus) { $focus = 'passwd2'; }
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

if ($msgs) {
	$afuncs->AddAttempt();
} elseif ($pass1) {
	if (!$fake) {
		$pw = $afuncs->UniqueToken($afuncs->GetConfig('password_min_length'));
		$hash = password_hash($pw, PASSWORD_DEFAULT);
		$data = json_encode(['temppass'=>$hash]);
		$sql = 'UPDATE '.$pref.'module_auth_sessions SET cache=? WHERE token=?';
		$db->Execute($sql, [$data, $token]);
		$sendmail = TRUE; //ignore context property!
		$res = $afuncs->addRequest($sdata['user_id'], $login, 'reset', $sendmail, $fake, $pw);
		if (!$res[0]) {
			$msgs[] = $res[1];
		} elseif (!$sendmail) {
			$msgs[] = $mod->Lang('TODO');
		}
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
	if ($lvl == Auther\Setup::CHALLENGED) {
		//cache $login, provided data (from $flds[])
		$data = json_encode($TODO);
		$enc = $cfuncs->encrypt_value($mod, $data);
		$sql = 'UPDATE '.$pref.'module_auth_sessions SET cache=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
		//TODO initiate challenge
	} else {
		$afuncs->resetPassword($token, $pw2, $pw2);
	}
}