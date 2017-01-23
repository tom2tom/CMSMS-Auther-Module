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

$avars = $_POST;
$this->Crash();

$scan = [];
$keys = array_keys($_POST);
foreach ($keys as $kn) {
	$p = substr($kn, 0, 7);
	if (array_key_exists($p, $scan)) {
		$scan[$p]++;
	} else {
		$scan[$p] = 1;
	}
}

$c = max($scan);
$id = array_search($c, $scan);
$kn = $id.'data';

if (empty($_POST[$kn])) {
	exit;
}

$mod = cms_utils::get_module('Auther');
$cfuncs = new Auther\Crypter();

$params = json_decode($cfuncs->decrypt_value($mod, base64_decode($_POST[$kn])));
if (empty($params) || $params['identity'] !== substr($id, 3, 3)) {
	exit;
}

$db = cmsms()->GetDb();
$pre = cms_db_prefix();
$cdata = $db->GetRow('SELECT * FROM '.$pre.'module_auth_contexts WHERE id=?', [$params['context']]);

$afuncs = new Auther\Auth($mod, $params['context']);

//TODO get & process other $_POST values

if ($_POST[$id.'jsok'] === 'OK') { //TODO && not-finished-now
//send stuff via ajax to user
} else {
//send stuff to $params['handler']
}

exit;
