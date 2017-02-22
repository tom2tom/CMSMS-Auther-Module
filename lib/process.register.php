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
$plogin = $id.'login';
$ppasswd = $id.'passwd';
$ppasswd2 = $id.'passwd2';
$pname = $id.'name';
$pcontact = $id.'contact';
$pcaptcha = $id.'captcha';
$postvars = filter_input_array(INPUT_POST, [
	$plogin => FILTER_SANITIZE_STRING,
	$ppasswd => FILTER_SANITIZE_STRING,
	$ppasswd2 => FILTER_SANITIZE_STRING,
	$pname => FILTER_SANITIZE_STRING,
	$pcontact => FILTER_SANITIZE_STRING,
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
	$flds = [];
	//common stuff
	$t = trim($postvars[$plogin]);
	if ($t) {
		$res = $afuncs->ValidateLogin($t);
		if ($res[0]) {
			if (0) { //TODO extra test criterion
				$res = $afuncs->SensibleLogin($t);
			}
		}
		if ($res[0]) {
			$res = $afuncs->UniqueLogin($t);
			if ($res[0]) {
				$flds['publicid'] = $t;
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

	$pw = ($jax) ? filter_var($sent['passwd'], FILTER_SANITIZE_STRING) : $postvars[$ppasswd];
	$pw = trim($pw);
	$res = $afuncs->ValidatePassword($pw);
	if ($res[0]) {
		$flds['privhash'] = $pw;
	} else {
		$msgs[] = $res[1];
		if (!$focus) { $focus = 'passwd'; }
	}
	if (!$jax) { //i.e. lengths not matched in browser
		$pw2 = trim($postvars[$ppasswd2]);
		if ($pw !== $pw2) {
			unset($flds['privhash']);
			$msgs[] = $mod->Lang('newpassword_nomatch'); //TODO not new
			if (!$focus) { $focus = 'passwd2'; }
		}
	}

	$t = trim($postvars[$pname]);
	if ($t) {
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
	} elseif ($cdata['name_required']) {
		$msgs[] = $mod->Lang('missing_type', $mod->Lang('name'));
		if (!$focus) { $focus = 'name'; }
	} else {
		$flds['name'] = '';
	}

	$t = trim($postvars[$pcontact]);
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

	switch ($lvl) {
	 case Auther::MIDSEC:
	//check stuff
		if (!$jax) {
			if ($params['captcha'] !== $postvars[$pcaptcha]) {
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
} //switch $lvl

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
