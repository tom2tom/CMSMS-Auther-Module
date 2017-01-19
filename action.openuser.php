<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$uid = (int)$params['user_id']; //-1 for new user
$pmod = ($uid == -1 || !empty($params['edit']));
if ($pmod && !($this->_CheckAccess('admin') || $this->_CheckAccess('user'))) {
	exit;
}

if (!function_exists('langhasval')) {
 function langhasval(&$mod, $key) {
	static $cmsvers = 0;
	static $trans;
	static $realm;

	if ($cmsvers == 0) {
		$cmsvers = ($mod->before20) ? 1:2;
		if ($cmsvers == 1) {
			$var = cms_current_language(); //CMSMS 1.8+
			$trans = $mod->langhash[$var];
		} else {
			$realm = $mod->GetName();
		}
	}
	if ($cmsvers == 1) {
		return (array_key_exists($key, $trans));
	} else {
		return (CmsLangOperations::key_exists($key, $realm));
	}
 }
}

if (isset($params['cancel'])) {
	$this->Redirect($id, 'users', '', ['context'=>$params['context']]); //TODO parms
} elseif (isset($params['submit'])) {
//TODO verify & save stuff
//TODO encrypt address,passhash
	$this->Redirect($id, 'users', '', ['context'=>$params['context']]);
}

$funcs = new Auther\Crypter();
if ($uid > -1) { //existing data
/*
id I KEY,
publicid C(48),
address B,
passhash B,
context I,
lastuse I,
active I(1) DEFAULT 1
*/
	$pre = cms_db_prefix();
	$sql = "SELECT * FROM {$pre}module_auth_users WHERE id=?";
	$data = $db->GetRow($sql,[$uid]);
	unset($data['lastuse']);
//TODO decrypt address,passhash
} else {
	$data = [
	'publicid' => $this->Lang('missingname'),
	'context' => $params['context'],
	'passhash' => '',
	'address' => '',
	'active' => 1
	];
}
//TODO get/set context name for display

$utils = new Auther\Utils();

$tplvars = ['mod' => $pmod];
$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = [
	'context'=>$params['context'],
	'user_id'=>$data['id'],
	'edit'=>!empty($params['edit'])
]; //TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'openuser',$returnid,'POST',
	'','','',$hidden);
$tplvars['endform'] = $this->CreateFormEnd();
if ($uid == -1) {
	$tplvars['title'] = $this->Lang('title_useradd');
} else {
	$tplvars['title'] = $this->Lang('title_userfull');
}
//$tplvars['desc'] = TODO;
$tplvars['compulsory'] = $this->Lang('compulsory_items');

$baseurl = $this->GetModuleURLPath();
$jsfuncs = []; //script accumulators
$jsloads = [];
$jsincs = [];

if (!$pmod) {
	$yes = $this->Lang('yes');
	$no = $this->Lang('no');
}

$options = [];
$one = new stdClass();
$one->title = $this->Lang('title_'.$kn);
$one->input = $this->CreateInputCheckbox($id, $kn, 1, $this->GetPreference($kn, 0));
$one->must = 0;
$kn = 'help_'.$kn;
if (langhasval($this, $kn)) {
	$one->help = $this->Lang($kn);
}
$options[] = $one;

$one = new stdClass();
$options[] = $one;

$one = new stdClass();
$options[] = $one;

$one = new stdClass();
$options[] = $one;

$one = new stdClass();
$options[] = $one;

$tplvars['options'] = $options;
if ($pmod) {
	$tplvars['submit'] = $this->CreateInputSubmit($id,'submit',$this->Lang('submit'));
	$tplvars['cancel'] = $this->CreateInputSubmit($id,'cancel',$this->Lang('cancel'));
} else {
	$tplvars['submit'] = NULL;
	$tplvars['cancel'] = $this->CreateInputSubmit($id,'cancel',$this->Lang('close'));
}

$jsall = $utils->MergeJS($jsincs, $jsfuncs, $jsloads);
unset($jsincs);
unset($jsfuncs);
unset($jsloads);

echo $utils->ProcessTemplate($this, 'openitem.tpl', $tplvars);
if ($jsall) {
	echo $jsall; //inject constructed js after other content
}
