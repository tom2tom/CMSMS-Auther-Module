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

$tblname = $pref.'module_auth_attempts';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

$tblname = $pref.'module_auth_requests';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

$tblname = $pref.'module_auth_sessions';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

$tblname = $pref.'module_auth_users';
$sql = $dict->DropTableSQL($tblname);
$dict->ExecuteSQLArray($sql);

$this->RemovePreference();

//$this->RemovePermission('SeeAuthProperties');
//$this->RemovePermission('ModifyAuthProperties');
$this->RemovePermission ('ReviewAuthStatus');
$this->RemovePermission ('SendAuthEvents');
