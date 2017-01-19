<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

if (!($this->_CheckAccess('admin') || $this->_CheckAccess('user'))) {
	exit;
}

$utils = new Auther\Utils();

if (isset($_FILES) && isset($_FILES[$id.'csvfile'])) {
	if (isset($params['item_id'])) {
		$which = $params['item_id'];
	} else {
		$which = '*';
	}
	$funcs = new Auther\Import();
	$res = $funcs->ImportUsers($this, $id, $which);
	$msg = $utils->PrettyMessage($this, $res[1], $res[0], FALSE);
	$newparms = ['message' => $msg];
	if ($which != '*') {
		$newparms['item_id'] = $which;
	}
	$this->Redirect($id, $params['resume'], '', $newparms);
}

$tplvars = [];
$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = ['resume'=>$params['resume']];
if (isset($params['item_id'])) {
	$hidden['item_id'] = $params['item_id'];
}
//TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'import',$returnid,'POST',
	'multipart/form-data','','', $hidden);
$tplvars['endform'] = $this->CreateFormEnd();
$tplvars['title'] = $this->Lang('title_import');
$tplvars['chooser'] = $this->CreateInputFile($id,'csvfile','text/csv',25);
$tplvars['apply'] = $this->CreateInputSubmit($id,'import',$this->Lang('upload'));
$tplvars['cancel'] = $this->CreateInputSubmit($id,'cancel',$this->Lang('cancel'));
$tplvars['help'] = $this->Lang('help_import');

echo $utils->ProcessTemplate($this, 'chooser.tpl', $tplvars);
