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

$lvl = $cdata['security_level'];
switch ($lvl) {
 case Auther\Setup::NOBOT:
	//nothing to do
	break;
 case Auther\Setup::LOSEC:
 case Auther\Setup::NONCED:
 case Auther\Setup::CHALLENGED:
	//common stuff
	$login = trim($_POST[$id.'login']);
	$t = ($jax) ? $sent['passwd'] : $_POST[$id.'passwd'];
	$pw = trim($t);
	$res = $vfuncs->IsKnown($login, $pw);
	if (!$res[0]) {
		$msgs[] = $res[1];
		$focus = 'login';
	}
	$t = ($jax) ? $sent['passwd2'] : $_POST[$id.'passwd2'];
	$pw2 = trim($t);
	if ($pw === $pw2) {
		$msgs[] = $mod->Lang('newpassword_match');
		if (!$focus) { $focus = 'passwd2'; }
	}
	$res = $afuncs->validatePassword($pw2);
	if (!$res[0]) {
		$msgs[] = $res[1];
		if (!$focus) { $focus = 'passwd2'; }
	}
	if (!$jax) { //i.e lengths not matched in browser
		if ($pw2 !== trim($_POST[$id.'passwd3'])) {
			$msgs[] = $mod->Lang('newpassword_nomatch');
			if (!$focus) { $focus = 'passwd2'; }
		}
	}
	if (!$msgs) {
		$flds['privhash'] = $pw2; //hash when required
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
	break;
 case Auther\Setup::HISEC:
 //TODO
	break;
}

if (!$msgs) {
	$t = trim($_POST[$id.'login']);
	if ($lvl == Auther\Setup::CHALLENGED) {
	//cache provided data (from $flds[] to session::cache)
	//also $login etc for rediscovery
		if (!$sdata) {
			$uid = $afuncs->getUID($t);
			$token = $afuncs->Y($uid);
		}
		//update session parameters
	//initiate challenge
	} else {
		$uid = $afuncs->getUID($t);
		$afuncs->changePassword($uid, $pw, $pw2, $pw2);
	//report success
	}
}
