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
//case :
}
/*
$dict = NewDataDictionary($db);
$pref = cms_db_prefix();
$sqlarray = $dict->RenameColumnSQL($pref.'module_auth_users','publicid','account','account B');
$ares = $dict->ExecuteSqlArray($sqlarray,FALSE);
//$sqlarray = $dict->AlterColumnSQL($pref.'module_auth_users','account B');
//$ares = $dict->ExecuteSqlArray($sqlarray,FALSE);
$sqlarray = $dict->AddColumnSQL($pref.'module_auth_users','acchash B');
$ares = $dict->ExecuteSqlArray($sqlarray,FALSE);
$sqlarray = ['ALTER TABLE '.$pref.'module_auth_users CHANGE acchash acchash longblob NULL AFTER account'];
$ares = $dict->ExecuteSqlArray($sqlarray,FALSE);
$sqlarray = $dict->RenameColumnSQL($pref.'module_auth_users','privreset','passreset','passreset I(1) DEFAULT 0');
$ares = $dict->ExecuteSqlArray($sqlarray,FALSE);
$sqlarray = $dict->RenameColumnSQL($pref.'module_auth_users','privhash','passhash','passhash B');
$ares = $dict->ExecuteSqlArray($sqlarray,FALSE);

$cfuncs = new Auther\Crypter($this);
$mpw = $this->GetPreference('masterpass');
if ($mpw) {
	$mpw = $cfuncs->olddecrypt_preference('masterpass');
	$cfuncs->encrypt_preference('masterpass',$mpw);
	$this->RemovePreference('masterpass');
} else {
	$mpw = $cfuncs->decrypt_preference('masterpass');
	if (!$mpw) {
		$mpw = 'Crack V4bNsgj1ws if you can!';
		$cfuncs->encrypt_preference('masterpass',$mpw);
	}
}

$sql = 'SELECT id,account FROM '.$pref.'module_auth_users';
$rst = $db->Execute($sql);
if ($rst) {
	$sql = 'UPDATE '.$pref.'module_auth_users SET account=?,acchash=? WHERE id=?';
	while (!$rst->EOF) {
		$login = $cfuncs->encrypt_value($rst->fields['account'], $mpw);
		$hash = $cfuncs->hash_value($rst->fields['account'], $mpw);
		$db->Execute($sql, [$login, $hash, $rst->fields['id']]);
		if (!$rst->MoveNext()) {
			break;
		}
	}
	$rst->Close();
}
//~~~~~~~~
$cfuncs = new Auther\Crypter($this);
$mpw = $cfuncs->decrypt_preference('masterpass');
$pref = cms_db_prefix();
$sql = 'SELECT id,account FROM '.$pref.'module_auth_users';
$rst = $db->Execute($sql);
if ($rst) {
	$sql = 'UPDATE '.$pref.'module_auth_users SET acchash=? WHERE id=?';
	while (!$rst->EOF) {
		$login = $cfuncs->decrypt_value($rst->fields['account'], $mpw);
		$hash = $cfuncs->hash_value($login, $mpw);
		$db->Execute($sql, [$hash, $rst->fields['id']]);
		if (!$rst->MoveNext()) {
			break;
		}
	}
	$rst->Close();
}
*/
