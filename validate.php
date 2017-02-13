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

// c.f. StripeGate::Payer
function notify_handler($params, $others=FALSE)
{
/*TODO sanitize $others - handlers tolerate any of the following (prefixed):
need explicit success / user_id / token /$id + the following:
'success' + 'user_id'
'repeat' + 'token'
'message'
'focus'
'html'
'cancel'
*/
//	$newparms = ['success'=>1];
//	$newparms = ['cancel'=>1];
	$newparms = $others; //TODO

	switch ($params['handlertype']) {
	 case 1: //callable, 2-member array or string like 'ClassName::methodName'
		$res = call_user_func_array($params['handler'], $newparms);
		//TODO handle $res == FALSE
		break;
/*	 case 2: //static closure not supported
		$res = $params['handler']($newparms);
		break; */
	 case 3: //module action
		$ob = \cms_utils::get_module($params['handler'][0]);
		$res = $ob->DoAction($params['handler'][1], $params['handler'][2], $newparms);
		unset($ob);
		//TODO handle $res == 400+
		break;
	 case 4: //code inclusion
		$ob = \cms_utils::get_module($params['handler'][0]);
		$fp = $ob->GetModulePath().DIRECTORY_SEPARATOR.$params['handler'][1].'.php';
		unset($ob);
		$res = FALSE;
		require $fp;
		break;
	 case 5: //code inclusion
		$res = FALSE;
		require $params['handler'];
		break;
	 case 6: //URL
		$ch = curl_init();
		//can't be bothered with GET URL construction
		curl_setopt_array($ch,[
		 CURLOPT_RETURNTRANSFER => 1,
		 CURLOPT_URL => $params['handler'],
		 CURLOPT_POST => 1,
		 CURLOPT_POSTFIELDS => $newparms
		]);
		$res = curl_exec($ch);
		//TODO handle $res == 400+
		curl_close($ch);
		break;
	}
}

//clear all page-content echoed before now
$handlers = ob_list_handlers();
if ($handlers) {
	$l = count($handlers);
	for ($c=0; $c<$l; $c++)
		ob_end_clean();
}

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

$kn = $id.'data';
if (empty($_POST[$kn])) {
	if ($jax) {
		ajax_errreport($mod->Lang('err_ajax'));
	} else {
		//handler N/A yet
		echo $mod->Lang('err_ajax');
	}
	exit;
}

$jax = !empty($_POST[$id.'jsworks']);
//grab stuff cuz' we've bypassed a normal session-start
$fp = __DIR__;
$c = strpos($fp, '/modules');
$inc = substr($fp, 0, $c+1).'include.php';
require $inc;

$mod = cms_utils::get_module('Auther');
$errmsg = $mod->Lang('err_ajax');

$cfuncs = new Auther\Crypter();
$pw = $cfuncs->decrypt_preference($mod, 'masterpass');
$iv = base64_decode($_POST[$id.'IV']);
$t = openssl_decrypt($_POST[$kn], 'BF-CBC', $pw, 0, $iv);
if (!$t) {
	if ($jax) {
		ajax_errreport($errmsg);
	} else {
		//handler N/A yet
		echo $errmsg;
	}
	exit;
}

$params = unserialize($t);
if (empty($params) || $params['identity'] !== substr($id, 2, 3)) {
	if ($jax) {
		ajax_errreport($errmsg);
	} else {
		//TODO signal something to handler
		if ($params) {
			notify_handler($params, $errmsg);
		} else {
			echo $errmsg;
		}
	}
	exit;
}

if (!empty($_POST[$id.'cancel'])) {
	//TODO pass to handler
	notify_handler($params, ['cancel'=>1]);
	exit;
}
if (!empty($_POST[$id.'success'])) {
	//TODO pass to handler
	notify_handler($params, ['success'=>1]);
	exit;
}

$iv = base64_decode($_POST[$id.'nearn']);
$iv = substr($iv, 0, 16); //force correct iv length
$t = openssl_decrypt($_POST[$id.'sent'], 'AES-256-CBC', $params['far'], 0, $iv);
if (!$t) {
	if ($jax) {
		ajax_errreport($errmsg);
	} else {
		//TODO signal something to handler
		notify_handler($params, $errmsg);
	}
	exit;
}
$p = strpos($t, $params['far']) + strlen($params['far']);
$sent = (array)json_decode(substr($t, $p));
if (!$sent) {
	if ($jax) {
		ajax_errreport($errmsg);
	} else {
		//TODO signal something to handler
		notify_handler($params, $errmsg);
	}
	exit;
}

$db = $gCms->GetDb(); //var defined by inclusion
$pref = cms_db_prefix();
$cdata = $db->GetRow('SELECT * FROM '.$pref.'module_auth_contexts WHERE id=?', [$params['context']]);
if (!empty($params['token'])) {
	$token = $params['token'];
	$sdata = $db->GetRow('SELECT * FROM '.$pref.'module_auth_cache WHERE token=?', [$token]);
} else {
	$token = FALSE; //may be updated by included code
	$sdata = FALSE;
}

$afuncs = new Auther\Auth($mod, $params['context']);
$vfuncs = new Auther\Validate($mod, $afuncs, $cfuncs);
$msgs = [];
$focus = '';
$forcereset = FALSE;

$task = (empty($_POST[$id.'recover'])) ? $params['task'] : 'recover';
require (__DIR__.DIRECTORY_SEPARATOR.'lib'.DIRECTORY_SEPARATOR.'process.'.$task.'.php');
if ($forcereset) {
	//TODO
}

if ($msgs) { //error
	$msgtext = implode("\n", $msgs); //newline for js alert box
	$t = ['message'=>$msgtext, 'focus'=>$focus];
	if ($jax) {
		header('HTTP/1.1 500 Internal Server Error');
	}
} elseif (0) { //TODO not-finished-now e.g. challenge
	$t = ['message'=>'I\'m back']; //TODO
	if ($jax) {
		header('HTTP/1.1 200 OK');
	}
} else {
	$t = ['success'=>1];
	if ($jax) {
		header('HTTP/1.1 202 Accepted');
	}
}

if ($jax) {
	header('Content-Type: application/json; charset=UTF-8');
	die(json_encode($t));
} else {
	notify_handler($params, $t);
	exit;
}
