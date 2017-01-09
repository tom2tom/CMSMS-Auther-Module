<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$taboptarray = array('mysql' => 'ENGINE MyISAM CHARACTER SET utf8 COLLATE utf8_general_ci',
 'mysqli' => 'ENGINE MyISAM CHARACTER SET utf8 COLLATE utf8_general_ci');
$dict = NewDataDictionary($db);
$pref = \cms_db_prefix();

//cookie_path','/');
//mail_charset C(16) DEFAULT 'UTF-8',
$flds = "
id I KEY,
name C(48) NOTNULL,
alias C(16) NOTNULL,
attack_mitigation_time C(16) DEFAULT '30 minutes',
attempts_before_ban I(1) DEFAULT 10,
attempts_before_verify I(1) DEFAULT 5,
bcrypt_cost I(2) DEFAULT 10,
cookie_domain C(32),
cookie_forget C(16) DEFAULT '30 minutes',
cookie_http I(1) DEFAILT 0,
cookie_name C(32) DEFAULT 'CMSMSauthID',
cookie_remember C(16) DEFAULT '1 month',
cookie_secure I(1) DEFAULT 0,
login_max_length I(1) DEFAULT 48,
login_min_length I(1) DEFAULT 5,
login_use_banlist I(1) DEFAULT 1,
password_min_length I(1) DEFAULT 8,
password_min_score I(1) DEFAULT 3,
request_key_expiration C(16) DEFAULT '10 minutes',
suppress_activation_message I(1) DEFAULT 0,
suppress_reset_message I(1) DEFAULT 0
";
$tblname = $pref.'module_auth_contexts';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_contexts_seq');

$flds = "
id I AUTO KEY,
ip C(39) NOTNULL,
expire I
";
$tblname = $pref.'module_auth_attempts';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$flds = "
id I KEY,
uid I NOTNULL,
expire I,
rkey C(32) NOTNULL,
type C(16) NOTNULL
";
$tblname = $pref.'module_auth_requests';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_requests_seq');

$flds = "
id I AUTO KEY,
uid I NOTNULL,
hash C(40) NOTNULL,
factor2 C(60),
expire I,
ip C(39) NOTNULL,
agent C(200) NOTNULL,
cookie_hash C(40) NOTNULL
";
$tblname = $pref.'module_auth_sessions';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$flds = "
id I KEY,
login C(48),
passhash C(60),
email C(96),
context I,
lastuse I,
isactive I(1) DEFAULT 0
";
$tblname = $pref.'module_auth_users';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_users_seq');

//TODO support extra, runtime-specified, user-parameters

$this->SetPreference('masterpass', 'OWFmNT1dGbU5FbnRlciBhdCB5b3VyIG93biByaXNrISBEYW5nZXJvdXMgZGF0YSE=');

$this->SetPreference('attack_mitigation_time', '30 minutes');
$this->SetPreference('attempts_before_ban', 10);
$this->SetPreference('attempts_before_verify', 5);
$this->SetPreference('bcrypt_cost', 10);
$this->SetPreference('context_sender', 'PHPAuth'); //for email messages
$this->SetPreference('context_email', 'no-reply@phpauth.cuonic.com'); //ditto
$this->SetPreference('cookie_domain', NULL);
$this->SetPreference('cookie_forget', '30 minutes');
$this->SetPreference('cookie_http', 0);
$this->SetPreference('cookie_name', 'CMSMSauthID');
//$this->SetPreference('cookie_path','/');
$this->SetPreference('cookie_remember', '1 month');
$this->SetPreference('cookie_secure', 0);

$this->SetPreference('login_max_length', 48);
$this->SetPreference('login_min_length', 5);
$this->SetPreference('login_use_banlist', 1);

$this->SetPreference('mail_charset', 'UTF-8');
$this->SetPreference('password_min_length', 8);
$this->SetPreference('password_min_score', 3);
$this->SetPreference('request_key_expiration', '10 minutes');

$this->SetPreference('session_key', 'kd8s2!7HVHG7777ghZfghuior.)\!/jdU');
/*
$this->SetPreference('site_activation_page','activate');
$this->SetPreference('site_email', 'no-reply@phpauth.cuonic.com');
$this->SetPreference('site_name','PHPAuth');
$this->SetPreference('site_password_reset_page','reset');
$this->SetPreference('site_timezone','Europe/Paris');
$this->SetPreference('site_url', 'https://github.com/PHPAuth/PHPAuth');

$this->SetPreference('smtp',0);
$this->SetPreference('smtp_auth',1);
$this->SetPreference('smtp_host','smtp.example.com');
$this->SetPreference('smtp_password','password');
$this->SetPreference('smtp_port',25);
$this->SetPreference('smtp_security',NULL);
$this->SetPreference('smtp_username','email@example.com');
*/
$this->SetPreference('suppress_activation_message', 0);
$this->SetPreference('suppress_reset_message', 0);

$this->CreateEvent('AuthRegister');
$this->CreateEvent('AuthDeregister');
$this->CreateEvent('AuthLogin');
$this->CreateEvent('AuthLoginFail');
$this->CreateEvent('AuthLogout');

$this->CreatePermission('ModifyAuthProperties', $this->Lang('perm_modify'));
$this->CreatePermission('ReviewAuthProperties', $this->Lang('perm_see'));
$this->CreatePermission('SendAuthEvents', $this->Lang('perm_send'));
