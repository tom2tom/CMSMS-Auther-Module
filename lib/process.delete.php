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
$plogin = $id.'login';
$ppasswd = $id.'passwd';
$pcaptcha = $id.'captcha';
$postvars = filter_input_array(INPUT_POST, [
	$plogin => FILTER_SANITIZE_STRING,
	$ppasswd => FILTER_SANITIZE_STRING,
	$pcaptcha => FILTER_SANITIZE_STRING
], FALSE);

$lvl = $cdata['security_level'];
switch ($lvl) {
 case Auther::NOBOT:
	//nothing to do
	break;
 case Auther::LOSEC:
 case Auther::MIDSEC:
 case Auther::CHALLENGED:
	//common stuff
	$login = trim($postvars[$plogin]);
	if (!$login) {
		$t = ($cdata['email_login']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
		$focus = 'login';
	}
	$t = ($jax) ? filter_var($sent['passwd'], FILTER_SANITIZE_STRING) : $postvars[$ppasswd];
	$pw = trim($t);
	if (!$pw) {
		$msgs[] = $mod->Lang('missing_type', $mod->Lang('password'));
		if (!$focus) { $focus = 'passwd'; }
	} elseif ($login) {
		$res = $afuncs->IsRegistered($login, $pw);
		if (!$res[0]) {
			$msgs[] = $res[1];
			$focus = 'login';
		}
	}
	break;
 case Auther::HISEC:
 //TODO
	break;
} //switch level

if ($msgs) {
	$afuncs->AddAttempt();
} else {
	if ($lvl == Auther::CHALLENGED) {
		$flds = ['login' => $login, 'passwd' => $pw];
		$enc = $cfuncs->encrypt_value($mod, json_encode($flds));
		$sql = 'UPDATE '.$pref.'module_auth_cache SET data=? WHERE token=?';
		$db->Execute($sql, [$enc, $token]);
//TODO initiate challenge
	} else {
		$res = $afuncs->DeleteUser($login, $pw);
		if (!$res[0]) {
			$msgs[] = $rest[1];
		}
	}
}
