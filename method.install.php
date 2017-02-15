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
id I(2) KEY,
name C(48) NOTNULL,
alias C(16) NOTNULL,
owner I DEFAULT -1,
default_password B,
request_key_expiration C(16) DEFAULT \'10 minutes\',
attack_mitigation_span C(16) DEFAULT \'30 minutes\',
attempts_before_ban I(1) DEFAULT 10,
attempts_before_action I(1) DEFAULT 3,
context_site C(40),
context_sender C(40),
context_address C(96),
cookie_name C(32) DEFAULT \'CMSMSauthID\',
cookie_forget C(16) DEFAULT \'30 minutes\',
cookie_remember C(16) DEFAULT \'1 week\',
name_required I(1) DEFAULT 0,
login_max_length I(1) DEFAULT 48,
login_min_length I(1) DEFAULT 5,
password_rescue I(1) DEFAULT 1,
address_required I(1) DEFAULT 1,
email_required I(1) DEFAULT 0,
email_login I(1) DEFAULT 0,
email_banlist I(1) DEFAULT 1,
message_charset C(16),
password_forget C(16),
password_min_length I(1) DEFAULT 8,
password_min_score I(1) DEFAULT 4,
security_level I(1) DEFAULT '.Auther\Setup::LOSEC.',
send_activate_message I(1) DEFAULT 1,
send_reset_message I(1) DEFAULT 1
';
$tblname = $pref.'module_auth_contexts';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_contexts_seq');

/* attempts now in cache table
$flds = '
id I AUTO KEY,
ip C(40) NOTNULL,
expire I(8)
';
$tblname = $pref.'module_auth_attempts';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);
*/

/* requests now in cache table type ('activate' or 'reset') >> type 1 or 2
/*$flds = '
id I KEY,
user_id I(4) NOTNULL,
expire I(8),
token C(24) NOTNULL,
type C(16) NOTNULL
';
$tblname = $pref.'module_auth_requests';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_requests_seq');
*/
$flds = '
id I AUTO KEY,
token C(24) NOTNULL,
ip C(40),
user_id I(4),
context_id I(2),
expire I(8),
lastmode I(1),
status I(1) DEFAULT 0,
defunct I(1) DEFAULT 0,
attempts I(1) DEFAULT 0,
challenge C(64),
cookie_hash C(40),
agent C(200),
data B
';
$tblname = $pref.'module_auth_cache';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$sql = $dict->CreateIndexSQL('idx_'.$tblname, $tblname, 'token');
$dict->ExecuteSQLArray($sql);

/*
NB name,address,addwhen (at least) NULL if unused, to enable COALESCE
*/
$flds = '
id I(4) KEY,
publicid C(48),
privhash B,
name B,
address B,
context_id I(2),
addwhen I(8),
lastuse I(8),
nameswap I(1) DEFAULT 0,
privreset I(1) DEFAULT 0,
active I(1) DEFAULT 1
';
$tblname = $pref.'module_auth_users';
$sql = $dict->CreateTableSQL($tblname, $flds, $taboptarray);
$dict->ExecuteSQLArray($sql);

$db->CreateSequence($pref.'module_auth_users_seq');

/* support for extra, runtime-specified, user-parameters
$flds = '
id I KEY,
user_id I(4),
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

$cfuncs = new Auther\Crypter();
$cfuncs->encrypt_preference($this, 'masterpass', base64_decode('U3VjayBpdCB1cCwgY3JhY2tlcnMh'));
$cfuncs->encrypt_preference($this, 'default_password', base64_decode('Y2hhbmdlfCMkIyR8QVNBUA==')); //score 4
$this->SetPreference('recaptcha_key','');
$this->SetPreference('recaptcha_secret','');

$this->SetPreference('address_required', 1);
$this->SetPreference('attack_mitigation_span', '30 minutes');
$this->SetPreference('attempts_before_ban', 10);
$this->SetPreference('attempts_before_action', 3);
$this->SetPreference('context_site', get_site_preference('sitename', 'CMSMS').' Website'); //for email messages
$this->SetPreference('context_sender', NULL); //ditto
$this->SetPreference('context_address', NULL); //ditto

//$this->SetPreference('cookie_domain', NULL);
$this->SetPreference('cookie_forget', '30 minutes');
//$this->SetPreference('cookie_http', 0);
$this->SetPreference('cookie_name', 'CMSMSauthID');
//$this->SetPreference('cookie_path', NULL);
$this->SetPreference('cookie_remember', '1 week');
//$this->SetPreference('cookie_secure', 0);

$this->SetPreference('email_banlist', 1);
//for email address checking by mailcheck.js
$this->SetPreference('email_domains', ''); //specific/complete domains for initial check
$this->SetPreference('email_subdomains', ''); //partial domains for secondary check
$this->SetPreference('email_topdomains', 'biz,co,com,edu,gov,info,mil,name,net,org'); //for final check
$this->SetPreference('email_login', 0);
$this->SetPreference('email_required', 0);

$this->SetPreference('login_max_length', 48);
$this->SetPreference('login_min_length', 5);

$this->SetPreference('message_charset', 'UTF-8');
$this->SetPreference('name_required', 0);
$this->SetPreference('password_forget', '');
//$this->SetPreference('password_max_length', 72); //for CRYPT_BLOWFISH
$this->SetPreference('password_min_length', 8);
$this->SetPreference('password_min_score', 4);
$this->SetPreference('password_rescue', 1);
$this->SetPreference('request_key_expiration', '10 minutes');

$this->SetPreference('security_level', Auther\Setup::LOSEC);
$this->SetPreference('send_activate_message', 1);
$this->SetPreference('send_reset_message', 1);

$utils = new Auther\Utils();
$t = $utils->RandomString(32, FALSE, FALSE);
$this->SetPreference('session_salt', $t);

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

//add default context
$t = $cfuncs->decrypt_preference($this, 'default_password');
$t = $cfuncs->encrypt_value($this, $t);
$sql = 'INSERT INTO '.$pref.'module_auth_contexts (id,name,alias,default_password) VALUES (0,?,"default",?)';
$db->Execute($sql, [$this->Lang('default'), $t]);
