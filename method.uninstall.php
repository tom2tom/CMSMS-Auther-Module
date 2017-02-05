<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$dict = NewDataDictionary($db);
$pref = cms_db_prefix();

$tblname = $pref.'module_auth_contexts';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

/*
$tblname = $pref.'module_auth_attempts';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);
*/
$tblname = $pref.'module_auth_requests';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

$tblname = $pref.'module_auth_sessions';
$sql = $dict->DropIndexSQL('idx_'.$tblname, $tblname);
$dict->ExecuteSQLArray($sql);
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

/*
$tblname = $pref.'module_auth_userprops';
$sql = $dict->DropIndexSQL('idx_'.$tblname, $tblname);
$dict->ExecuteSQLArray($sql);
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);
*/

$tblname = $pref.'module_auth_users';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

$db->DropSequence($pref.'module_auth_contexts_seq');
$db->DropSequence($pref.'module_auth_requests_seq');
$db->DropSequence($pref.'module_auth_users_seq');

$this->RemovePreference();

$this->RemoveEvent('AuthRegister');
$this->RemoveEvent('AuthDeregister');
$this->RemoveEvent('AuthLogin');
$this->RemoveEvent('AuthLoginFail');
$this->RemoveEvent('AuthLogout');

$this->RemovePermission('AuthModuleAdmin');
$this->RemovePermission('AuthModifyContext');
$this->RemovePermission('AuthModifyUser');
$this->RemovePermission('AuthView');
//$this->RemovePermission('AuthSendEvents');
