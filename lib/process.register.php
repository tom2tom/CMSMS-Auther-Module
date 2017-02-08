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

$flds = [];
$lvl = $cdata['security_level'];
switch ($lvl) {
 case Auther\Setup::NOBOT:
	//nothing to do
	break;
 case Auther\Setup::LOSEC:
 case Auther\Setup::NONCED:
 case Auther\Setup::CHALLENGED:
	//common stuff
	$t = trim($_POST[$id.'login']);
	if ($t) {
		$res = $afuncs->validateLogin($t);
		if ($res[0]) {
			if ($afuncs->isLoginTaken($t)) {
				$msgs[] = $mod->Lang('login_notvalid'); //NOT explicit in-use message!
				$focus = 'login';
			} else {
				$flds['publicid'] = $t;
			}
		} else {
			$msgs[] = $res[1];
			$focus = 'login';
		}
	} else {
		$t = ($cdata['email_required']) ? 'title_email':'title_identifier';
		$msgs[] = $mod->Lang('missing_type', $mod->Lang($t));
		$focus = 'login';
	}
	$pw = ($jax) ? $sent['passwd'] : $_POST[$id.'passwd'];
	$pw = trim($pw);
	$res = $afuncs->validatePassword($pw);
	if (!$res[0]) {
		$msgs[] = $res[1];
		if (!$focus) { $focus = 'passwd'; }
	}
	if (!$jax) { //i.e. lengths not matched in browser
		$pw2 = trim($_POST[$id.'passwd2']);
		if ($pw !== $pw2) {
			$msgs[] = $mod->Lang('newpassword_nomatch'); //TODO not new
			if (!$focus) { $focus = 'passwd2'; }
		}
	}
	if (!$msgs) {
		$flds['privhash'] = $pw; //hash if/when needed
	}

	$t = trim($_POST[$id.'name']);
	if ($t) {
//		$t = X::SanitizeName($t); TODO cleanup whitespace etc
		$res = $afuncs->validateName($t);
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

	$t = trim($_POST[$id.'contact']);
	if ($t) {
		$res = $afuncs->validateAddress($t);
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
	if ($lvl == Auther\Setup::CHALLENGED) {
	//cache provided data (from $flds[] to session::cache)
	//initiate challenge
	} else {
		$res = $afuncs->addUser($flds['publicid'], $pw, $flds['name'], $flds['address'], $sendmail, []);
		if ($res[0]) {
			$uidnew = $res[1]; //for use by includer
		} else {
			$msgs[] = $res[1];
		}

	}
}
