<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

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
	exit;
}

//grab stuff cuz' we've bypassed a normal session-start
$fp = __DIR__;
$c = strpos($fp, '/modules');
$inc = substr($fp, 0, $c+1).'include.php'; 
require $inc;

$mod = cms_utils::get_module('Auther');

$cfuncs = new Auther\Crypter();
$pw = $cfuncs->decrypt_preference($mod, 'masterpass');
$t = openssl_decrypt($_POST[$kn], 'BF-CBC', $pw, 0, $_POST[$id.'IV']);
if (!$t) {
	exit;
}
$params = (array)json_decode($t);
if (empty($params) || $params['identity'] !== substr($id, 2, 3)) {
	exit;
}

$db = cmsms()->GetDb();
$pre = cms_db_prefix();
$cdata = $db->GetRow('SELECT * FROM '.$pre.'module_auth_contexts WHERE id=?', [$params['context']]);

$afuncs = new Auther\Auth($mod, $params['context']);

//TODO get & process other $_POST values

$adbg = json_decode(
'{"iv":"wvdG7+KjzXKRWuDPgHhfig==",
"v":1,
"iter":1000,
"ks":128,
"ts":64,
"mode":"ccm",
"adata":"This%20is%20my%20nonce",
"cipher":"aes",
"salt":"7LAtmkELhSc=",
"ct":"w1wAR4pw1/v25GXqPWb1BuRIF9B+jImzoNBnqUlKPEnQEZlB4iG57UxaiwuOfq3m1/i7eRGBWBhy"}'
);
$adbg2 = $adbg->iv;

$avars = $_POST;
$X = $Y;

/* sjcl output = string
{
"iv":"wvdG7+KjzXKRWuDPgHhfig==",
"v":1,
"iter":1000,
"ks":128,
"ts":64,
"mode":"ccm",
"adata":"This%20is%20my%20nonce",
"cipher":"aes",
"salt":"7LAtmkELhSc=",
"ct":"w1wAR4pw1/v25GXqPWb1BuRIF9B+jImzoNBnqUlKPEnQEZlB4iG57UxaiwuOfq3m1/i7eRGBWBhy"
}
*/

if ($_POST[$id.'jsworks'] !== '') { //TODO && not-finished-now
//send stuff via ajax to user
} else {
//send stuff to $params['handler']
}

exit;
