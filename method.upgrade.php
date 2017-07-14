<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$dict = NewDataDictionary($db);
$pref = \cms_db_prefix();

switch ($oldversion) {
/*
case :
$sqlarray = $dict->AlterColumnSQL($pref.'module_auth_users', 'account B');
$dict->ExecuteSqlArray($sqlarray);
$sql = 'SELECT id,account FROM '.$pref.'module_auth_users';
$rst = $db->Execute($sql);
if ($rst) {
	$cfuncs = new Auther\Crypter($this);
	$pw = $cfuncs->decrypt_preference('masterpass');
	$sql = 'UPDATE '.$pref.'module_auth_users SET account=? WHERE id=?';
	while (!$rst->EOF) {
		$login = $cfuncs->encrypt_value($rst->fields['account'], $pw);
		$db->Execute($sql, [$login, $rst->fields['id']]);
		if (!$rst->MoveNext()) {
			break;
		}
	}
	$rst->Close();
}
*/
}
