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

function ajax_abort() {
	header('HTTP/1.1 204 No Content');
	header('Content-Type: application/json; charset=UTF-8');
	echo(json_encode(0));
}

// c.f. StripeGate::Payer
function notify_handler($params, $others=FALSE)
{
/*TODO sanitize $others - handlers tolerate any of the following (prefixed):
need explicit success / user_id / token /$id + the following:
'success'
'cancel'
'message'
'repeat'
'task'
'token'
'focus'
'html'
*/
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
		$ob = cms_utils::get_module($params['handler'][0]);
		$res = $ob->DoAction($params['handler'][1], $params['handler'][2], $newparms);
		unset($ob);
		//TODO handle $res == 400+
		break;
/*	 case 4: //code inclusion NOT POSSIBLE WHEN 'repeat' MAY BE NECESSARY
		$ob = cms_utils::get_module($params['handler'][0]);
		$fp = $ob->GetModulePath().DIRECTORY_SEPARATOR.$params['handler'][1].'.php';
		unset($ob);
		$res = FALSE;
		require $fp;
		break;
	 case 5: //code inclusion
		$res = FALSE;
		require $params['handler'];
		break;
*/
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
	//TODO mimic javascript::location.reload(true);
	exit;
}

//string variables are filtered by FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW
function collect_post($id, $keys)
{
	$postvars = [];
	foreach ($keys as $k) {
		$key = $id.$k;
		if (isset($_POST[$key])) {
			$t = $_POST[$key];
			if (is_numeric($t)) {
				$t += 0;
			} elseif (is_string($t)) {
				if ($t) {
					$t = filter_var($t, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);
				}
			} else {
				$t = NULL;
			}
		} else {
			$t = NULL;
		}
		$postvars[$k] = $t;
	}
	return $postvars;
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

//grab stuff cuz' we've bypassed a normal session-start
$fp = __DIR__;
$c = strpos($fp, '/modules');
$inc = substr($fp, 0, $c+1).'include.php';
require $inc;

$jax = !empty($_POST[$id.'jsworks']);
$mod = cms_utils::get_module('Auther');
$errmsg = $mod->Lang('err_ajax');

$cfuncs = new Auther\Crypter($mod);
$mpw = $cfuncs->decrypt_preference(Auther\Crypter::MKEY);
$iv = base64_decode($_POST[$id.'IV']);
$t = openssl_decrypt($_POST[$kn], 'BF-CBC', $mpw, 0, $iv);
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
		if ($params) {
			$others = ['authdata' => base64_encode(json_encode((object)['error'=>1,'message'=>$errmsg]))];
			notify_handler($params, $others);
		} else {
			echo $errmsg;
		}
	}
	exit;
}

$afuncs = new Auther\Auth($mod, $params['context']);
$vfuncs = new Auther\Validate($mod, $afuncs, $cfuncs);

if (isset($_POST[$id.'success'])) {
	$postvars = collect_post($id, ['authdata']);
	if ($postvars['authdata']) {
		$t = $vfuncs->FilteredString($postvars['authdata']);
		if ($t == $postvars['authdata']) {
			$others = ['authdata' => $postvars['authdata']];
		} else {
			ajax_errreport($this->Lang('err_parm'));
		}
	} else {
		$others = ['authdata' => base64_encode(json_encode((object)['success'=>1]))];
	}
	notify_handler($params, $others);
	exit;
} elseif (isset($_POST[$id.'cancel'])) {
	$others = ['authdata' => base64_encode(json_encode((object)['cancel'=>1]))];
	notify_handler($params, $others);
	exit;
}

if (isset($_POST[$id.'sent'])) {
	$iv = base64_decode($_POST[$id.'nearn']);
	$iv = substr($iv, 0, 16); //force correct iv length
	$t = openssl_decrypt($_POST[$id.'sent'], 'AES-256-CBC', $params['far'], 0, $iv);
	if (!$t) {
		if ($jax) {
			ajax_errreport($errmsg);
		} else {
			$others = ['authdata' => base64_encode(json_encode((object)['message'=>$errmsg]))];
			notify_handler($params, $others);
		}
		exit;
	}
	$p = strpos($t, $params['far']) + strlen($params['far']);
	$ob = json_decode(substr($t, $p));
	if ($ob !== NULL) {
		$sent = (array)$ob;
	} else {
		if ($jax) {
			ajax_errreport($errmsg);
		} else {
			$others = ['authdata' => base64_encode(json_encode((object)['error'=>1,'message'=>$errmsg]))];
			notify_handler($params, $others);
		}
		exit;
	}
}

$db = $gCms->GetDb(); //var defined by inclusion
$pref = cms_db_prefix();
if (!empty($params['token'])) {
	$token = $params['token'];
	$sdata = $db->GetRow('SELECT * FROM '.$pref.'module_auth_cache WHERE token=?', [$token]); //maybe FALSE
} else {
	$token = FALSE; //may be updated by included code
	$sdata = FALSE;
}

if (!empty($_POST[$id.'recover'])) {
	$token = !empty($sdata['token']) ? $sdata['token'] : '';
	if ($jax) {
		ajax_abort();
		$others = ['TODO'];
	} else {
		$postvars = collect_post($id, ['authdata']);
		$others = FALSE;
		if ($postvars['authdata']) {
			$t = $vfuncs->FilteredString($postvars['authdata']);
			if ($t == $postvars['authdata']) {
				$others = ['authdata' => $postvars['authdata']];
			}
		}
		if (!$others) {
			echo $this->Lang('err_parm');
			exit;
		}
	}
	notify_handler($params, $others);
	exit;
}

$cdata = $db->GetRow('SELECT * FROM '.$pref.'module_auth_contexts WHERE id=?', [$params['context']]);
$lvl = $cdata['security_level'];
$msgs = [];
$focus = '';
$forcereset = FALSE;

$task = $params['task'];
require (__DIR__.DIRECTORY_SEPARATOR.'lib'.DIRECTORY_SEPARATOR.'process.'.$task.'.php');
if ($forcereset) {
	if ($jax) {
		//trigger another request
		header('HTTP/1.1 206 Validation Renew');
		header('Content-Type: application/json; charset=UTF-8');
		die(json_encode(0));
	}
	//CHECKME also send 'message' => 'whatever' e.g. $msgs[] ? 'html' => 'whatever' ? 'focus' => whatever
	$t = ['repeat'=>1, 'task'=>'reset', 'token'=>$sdata['token']];
	$others = ['authdata' => base64_encode(json_encode((object)$t))];
	notify_handler($params, $others);
	exit;
}

if ($msgs) { //error
	$msgtext = implode("\n", $msgs); //newline for js alert box
	$t = ['message'=>$msgtext, 'focus'=>$focus];
	if ($jax) {
		header('HTTP/1.1 540 Validation Failure'); //jQuery ajax accepts non-standard error code and/or text
	}
} elseif (0) { //TODO not-finished-now e.g. challenge
	$t = ['message'=>'I\'m back']; //TODO
	if ($jax) {
		header('HTTP/1.1 200 OK');
	}
} else {
	$t = ['success'=>1, 'message'=>$msgtext];
	if ($jax) {
		header('HTTP/1.1 202 Accepted');
	}
}

if ($jax) {
	header('Content-Type: application/json; charset=UTF-8');
	die(json_encode($t));
} else {
	$others = ['authdata' => base64_encode(json_encode((object)$t))];
	notify_handler($params, $others);
	exit;
}
