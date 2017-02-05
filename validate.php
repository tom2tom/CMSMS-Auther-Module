<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

function ajax_errreport($msg) {
	header('HTTP/1.1 500 Internal Server Error');
	header('Content-Type: application/json; charset=UTF-8');
	die(json_encode(['message'=>$msg, 'focus'=>'']));
}

//clear all page-content echoed before now
$handlers = ob_list_handlers();
if ($handlers) {
	$l = count($handlers);
	for ($c=0; $c<$l; $c++)
		ob_end_clean();
}

/*//TODO workaround dodgy json-parsing
$t = key($_POST);
if (strlen($t) > 40) {
	$_POST = (array)json_decode($t.reset($_POST));
}
*/
$scan = [];
$keys = array_keys($_POST);
foreach ($keys as $kn) {
	$t = substr($kn, 0, 6);
	if (array_key_exists($t, $scan)) {
		$scan[$t]++;
	} else {
		$scan[$t] = 1;
	}
}
$c = max($scan);
$id = array_search($c, $scan);

$jax = !empty($_POST[$id.'jsworks']);
//grab stuff cuz' we've bypassed a normal session-start
$fp = __DIR__;
$c = strpos($fp, '/modules');
$inc = substr($fp, 0, $c+1).'include.php';
require $inc;

$mod = cms_utils::get_module('Auther');

$kn = $id.'data';
if (empty($_POST[$kn])) {
	//TODO signal something
	if ($jax) {
		ajax_errreport($mod->Lang('err_ajax'));
	} else {
	}
	exit;
}

$cfuncs = new Auther\Crypter();
$pw = $cfuncs->decrypt_preference($mod, 'masterpass');
$iv = base64_decode($_POST[$id.'IV']);
$t = openssl_decrypt($_POST[$kn], 'BF-CBC', $pw, 0, $iv);
if (!$t) {
	//TODO signal something
	if ($jax) {
		ajax_errreport($mod->Lang('err_ajax'));
	} else {
	}
	exit;
}

$params = unserialize($t);
if (empty($params) || $params['identity'] !== substr($id, 2, 3)) {
	//TODO signal something
	if ($jax) {
		ajax_errreport($mod->Lang('err_ajax'));
	} else {
	}
	exit;
}

$iv = base64_decode($_POST[$id.'nearn']);
$iv = substr($iv, 0, 16); //force correct iv length
$t = openssl_decrypt($_POST[$id.'sent'], 'AES-256-CBC', $params['far'], 0, $iv);
if (!$t) {
	//TODO signal something
	if ($jax) {
		ajax_errreport($mod->Lang('err_ajax'));
	} else {
	}
	exit;
}
$p = strpos($t, $params['far']) + strlen($params['far']);
$sent = (array)json_decode(substr($t, $p));
if (!$sent) {
	//TODO signal something
	if ($jax) {
		ajax_errreport($mod->Lang('err_ajax'));
	} else {
	}
	exit;
}

$db = $gCms->GetDb(); //var defined by inclusion
$pre = cms_db_prefix();
$cdata = $db->GetRow('SELECT * FROM '.$pre.'module_auth_contexts WHERE id=?', [$params['context']]);
if (!empty($params['token'])) {
	$token = $params['token'];
	$sdata = $db->GetRow('SELECT * FROM '.$pre.'module_auth_sessions WHERE token=?', [$token]);
} else {
	$token = FALSE; //may be updated by included code
	$sdata = FALSE;
}

$afuncs = new Auther\Auth($mod, $params['context']);
$vfuncs = new Auther\Validate($mod, $afuncs, $cfuncs);
$msgs = [];
$focus = '';

/*TODO get & process $_POST array e.g.
[pA762_IV]	"Ys1ad0tN0JI="
[pA762_data]	"xD+qbcJIMUA87rNvZuppgYyCb2Ox04ChJj6jma8O7b/lwKuFC7yHoDwFH6buzxhLw2Ur/x0FonEwT6lMCotElxFLUcaHK9zvH1Wquo75vYWqC7pNbkBkonvKATq+semQA0xPCHuDsOw8nMVyFs84ctr0KRv/an3DVozCr8t35B23PWyBlKMv4xIySW3UoZ5942ReppZ99I4QZBma9YVvBwP0nyyL6+odS6bowic1nBgIQXjOYKs+gtqxiciS2DI18eAxWd0K+bJprgPHT000KjTNyxqoF5M+20Sapp5Bn7o6G2BaqLwPIQ=="
[pA762_jsworks]	"TRUE" iff ajax-sourced
[pA762_submit]	"Submit" iff NOT ajax-sourced
[pA762_captcha]	"text" maybe iff NOT ajax-sourced
[pA762_login]	"rogerrabbit"
[pA762_nearn]	"AjsxOcOYMMOSw77DkWAmwoAXw53Cun0"
[pA762_name]	"whatever" iff relevant for the mode
[pA762_contact]	"whatever" iff relevant for the mode
[pA762_recover]	"0" OR "1"
encrypted password(s) in
[pA762_sent]	"AjsxOcOYMMOSw77DkWAmwnb+nrh+HVJTjx6nelaIfxTfPBeyVqfR83gAhBd59lSk
y1ePAujBNoQstmmiebMRRAyhPAh5SvNK29Zlr2J77T7efx/y5heYyyf+5jyveKbu"
THE LATTER BECOMES
$sent array e.g.
[passwd] => "s11kul52"
[passwd2] => "someother" (if relevant)
*/

require (__DIR__.DIRECTORY_SEPARATOR.'process.'.$this->task.'.php');

if ($msgs) { //error
	$msgtext = implode('\n', $msgs); //newline for js alert box
	$t = json_encode(['message'=>$msgtext, 'focus'=>$focus]);
	if ($jax) {
		header('HTTP/1.1 500 Internal Server Error');
		header('Content-Type: application/json; charset=UTF-8');
		die($t);
	} else {
		//send stuff to $params['handler']
	}
} elseif (1) { //TODO not-finished-now
$t = 'I\'m back';
	if ($jax) {
		header('HTTP/1.1 204 No Content');
		header('Content-Type: application/json; charset=UTF-8');
		die($t);
	} else {
		//send stuff to $params['handler']
	}
} else {
	//send stuff to $params['handler']
}

exit;
