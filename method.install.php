<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$taboptarray = ['mysql' => 'ENGINE MyISAM CHARACTER SET utf8 COLLATE utf8_general_ci',
 'mysqli' => 'ENGINE MyISAM CHARACTER SET utf8 COLLATE utf8_general_ci'];
$dict = NewDataDictionary($db);
$pref = \cms_db_prefix();

//cookie_path C(48), // DEFAULT \'/\'
//message_charset C(16) DEFAULT 'UTF-8',
//cookie_secure I(1) DEFAULT 0,
//cookie_http I(1) DEFAULT 0,
//cookie_domain C(48),
$flds = '
id I KEY,
name C(48) NOTNULL,
alias C(16) NOTNULL,
request_key_expiration C(16) DEFAULT \'10 minutes\',
attack_mitigation_span C(16) DEFAULT \'30 minutes\',
attempts_before_ban I(1) DEFAULT 10,
attempts_before_verify I(1) DEFAULT 5,
cookie_name C(32) DEFAULT \'CMSMSauthID\',
cookie_forget C(16) DEFAULT \'30 minutes\',
cookie_remember C(16) DEFAULT \'1 week\',
login_max_length I(1) DEFAULT 48,
login_min_length I(1) DEFAULT 5,
address_required I(1) DEFAULT 0,
email_required I(1) DEFAULT 0,
email_banlist I(1) DEFAULT 1,
password_min_length I(1) DEFAULT 8,
password_min_score I(1) DEFAULT 4,
security_level I(1) DEFAULT '.Auther::LOSEC.'.
send_activate_message I(1) DEFAULT 1,
send_reset_message I(1) DEFAULT 1
';
$tblname = $pref.'module_auth_contexts';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_contexts_seq');

$flds = '
id I AUTO KEY,
ip C(39) NOTNULL,
expire I
';
$tblname = $pref.'module_auth_attempts';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$flds = '
id I KEY,
uid I NOTNULL,
expire I,
rkey C(32) NOTNULL,
type C(16) NOTNULL
';
$tblname = $pref.'module_auth_requests';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_requests_seq');

$flds = '
id I AUTO KEY,
uid I NOTNULL,
hash C(40) NOTNULL,
challenge C(60),
expire I,
ip C(39) NOTNULL,
agent C(200) NOTNULL,
cookie_hash C(40) NOTNULL
';
$tblname = $pref.'module_auth_sessions';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$flds = '
id I KEY,
publicid C(48),
passhash C(60),
address C(96),
context I,
addwhen I,
lastuse I,
active I(1) DEFAULT 1
';
$tblname = $pref.'module_auth_users';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_users_seq');

/* support for extra, runtime-specified, user-parameters
$flds = '
id I KEY,
uid I,
name C(256),
value C('.Auther::LENSHORTVAL.'),
longvalue B
';
$tblname = $pref.'module_auth_userprops';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->Execute('CREATE INDEX '.$tblname.'_idx ON '.$tblname.' (uid)');
$db->CreateSequence($pref.'module_auth_userprops_seq');
*/

$funcs = new Auther\Crypter();
$funcs->encrypt_preference($this, 'masterpass', base64_decode('U3VjayBpdCB1cCwgY3JhY2tlcnMh'));

$this->SetPreference('address_required' 0);
$this->SetPreference('attack_mitigation_span', '30 minutes');
$this->SetPreference('attempts_before_ban', 10);
$this->SetPreference('attempts_before_verify', 5);
$this->SetPreference('context_sender', NULL); //for email messages TODO site-name
$this->SetPreference('context_address', NULL); //ditto

//$this->SetPreference('cookie_domain', NULL);
$this->SetPreference('cookie_forget', '30 minutes');
//$this->SetPreference('cookie_http', 0);
$this->SetPreference('cookie_name', 'CMSMSauthID');
//$this->SetPreference('cookie_path', NULL);
$this->SetPreference('cookie_remember', '1 week');
//$this->SetPreference('cookie_secure', 0);

$this->SetPreference('email_banlist', 1);
$this->SetPreference('email_required', 0);

$this->SetPreference('login_max_length', 48);
$this->SetPreference('login_min_length', 5);

$this->SetPreference('message_charset', 'UTF-8');
//$this->SetPreference('password_max_length', 72); //for CRYPT_BLOWFISH
$this->SetPreference('password_min_length', 8);
$this->SetPreference('password_min_score', 4);
$this->SetPreference('request_key_expiration', '10 minutes');

$this->SetPreference('security_level', Auther::LOSEC);
$this->SetPreference('send_activate_message', 1);
$this->SetPreference('send_reset_message', 1);
$t = 'kd8s2!7HVHG7777ghZfghuior.)\!/jU'; //32-bytes
$this->SetPreference('session_salt', str_shuffle($t));
$this->SetPreference('use_context_sender', 0);

$this->CreateEvent('AuthRegister');
$this->CreateEvent('AuthDeregister');
$this->CreateEvent('AuthLogin');
$this->CreateEvent('AuthLoginFail');
$this->CreateEvent('AuthLogout');

$this->CreatePermission('AuthModuleAdmin', $this->Lang('perm_modify'));
$this->CreatePermission('AuthModifyContext', $this->Lang('perm_modcontext'));
$this->CreatePermission('AuthModifyUser', $this->Lang('perm_moduser'));
$this->CreatePermission('AuthView', $this->Lang('perm_see'));
//$this->CreatePermission('AuthSendEvents', $this->Lang('perm_send'));
