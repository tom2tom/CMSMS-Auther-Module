<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$dict = NewDataDictionary($db);
$pref = cms_db_prefix();

function account_rehash(&$cfuncs)
{
	global $db, $pref;
	$sql = 'SELECT id,account FROM '.$pref.'module_auth_users';
	$rst = $db->Execute($sql);
	if ($rst) {
		$sql = 'UPDATE '.$pref.'module_auth_users SET acchash=? WHERE id=?';
		$pw = $cfuncs->decrypt_preference(Auther\Crypter::MKEY);
		while (!$rst->EOF) {
			$login = $cfuncs->uncloak_value($rst->fields['account'], $pw);
			$hash = $cfuncs->hash_value($login, $pw);
			$db->Execute($sql, [$hash, $rst->fields['id']]);
			if (!$rst->MoveNext()) {
				break;
			}
		}
		$rst->Close();
	}
}

switch ($oldversion) {
 case '0.2':
	$sqlarray = $dict->RenameColumnSQL($pref.'module_auth_users', 'publicid', 'account', 'account B');
	$dict->ExecuteSqlArray($sqlarray, FALSE);
	$sqlarray = $dict->AlterColumnSQL($pref.'module_auth_users', 'account B');
	$dict->ExecuteSqlArray($sqlarray, FALSE);
	$sqlarray = $dict->RenameColumnSQL($pref.'module_auth_users', 'privreset', 'passreset', 'passreset I(1) DEFAULT 0');
	$dict->ExecuteSqlArray($sqlarray, FALSE);
	$sqlarray = $dict->RenameColumnSQL($pref.'module_auth_users', 'privhash', 'passhash', 'passhash B');
	$dict->ExecuteSqlArray($sqlarray, FALSE);
	$sqlarray = $dict->AddColumnSQL($pref.'module_auth_users', 'acchash B');
	$dict->ExecuteSqlArray($sqlarray, FALSE);

	$cfuncs = new Auther\Crypter($this);
	$t = $this->GetPreference('nQCeESKBr99A');
	if ($t) {
		$val = hash('crc32b', $t.$config['ssl_url'].$this->GetModulePath());
		$this->RemovePreference('nQCeESKBr99A');

		$key = 'masterpass';
		$s = base64_decode($this->GetPreference($key));
		$pw = $cfuncs->decrypt($s, $val);
		if (!$pw) {
			$pw = base64_decode('RW50ZXIgYXQgeW91ciBvd24gcmlzayEgRGFuZ2Vyb3VzIGRhdGEh');
		}
		$this->RemovePreference($key);
		$cfuncs->init_crypt();
		$cfuncs->encrypt_preference(Auther\Crypter::MKEY, $pw);

		foreach (['default_password', 'recaptcha_secret'] as $key) {
			$s = base64_decode($this->GetPreference($key));
			$t = $cfuncs->decrypt($s, $val);
			$this->RemovePreference($key);
			$cfuncs->encrypt_preference($key, $t);
		}
	} else {
		$pw = $cfuncs->decrypt_preference(Auther\Crypter::MKEY);
	}

	$sql = 'SELECT id,account,name,address FROM '.$pref.'module_auth_users';
	$rst = $db->Execute($sql);
	if ($rst) {
		$sql = 'UPDATE '.$pref.'module_auth_users SET account=?,acchash=?,name=?,address=? WHERE id=?';
		while (!$rst->EOF) {
			$t = $cfuncs->decrypt_value($rst->fields['account'], $pw);
			$hash = $cfuncs->hash_value($t, $pw);
			$login = $cfuncs->cloak_value($t, 16, $pw);
			$t = $cfuncs->decrypt_value($rst->fields['name'], $pw);
			$name = ($t) ? $cfuncs->cloak_value($t, 0, $pw) : NULL;
			$t = $cfuncs->decrypt_value($rst->fields['address'], $pw);
			$address = ($t) ? $cfuncs->cloak_value($t, 24, $pw) : NULL;

			$db->Execute($sql, [$login, $hash, $name, $address, $rst->fields['id']]);
			if (!$rst->MoveNext()) {
				break;
			}
		}
		$rst->Close();
	}
// case '':
//	account_rehash($cfuncs);
}
