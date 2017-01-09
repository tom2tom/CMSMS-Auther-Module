<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

function langval(&$mod, $key, $def) {
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
		if (array_key_exists($key, $trans)) {
			//NOTE $trans[] values could be any encoding
			//use $mod->Lang($k) to transcode to UTF-8, interpret embedded params etc
			return $trans[$key];
		} else {
			return $def;
		}
	} else {
		if (CmsLangOperations::key_exists($key, $realm)) {
			return CmsLangOperations::lang_from_realm($realm, $key);
		} else {
			return $def;
		}
	}
}

$pdev = $this->CheckPermission('Modify Any Page');
$pset = $this->_CheckAccess('module');
$padm = $pset || $this->_CheckAccess('admin');
if ($padm) {
//	$psee = TRUE;
	$padd = TRUE;
	$pdel = TRUE;
	$pmod = TRUE;
	$pbkg = TRUE;
	$pper = TRUE;
	$pset = TRUE;
} else {
//	$psee = $this->_CheckAccess('view');
	$padd = $this->_CheckAccess('add');
	$pdel = $this->_CheckAccess('delete');
	$pmod = $this->_CheckAccess('modify');
	$pbkg = $this->_CheckAccess('book');
	$pper = $this->_CheckAccess('booker');
	$pset = $this->_CheckAccess('Modify Auth Settings');
}

$mod = $padm || $pmod;
$bmod = $padm || $pbkg;

if (isset($params['submit'])) {
	//save settings
	foreach ($params as $kn=>$val) {
		if (strncmp ($kn, 'pref_', 5) == 0) {
			$kn = substr($kn, 5);
			//validate, process
			$this->SetPreference($kn, $val);
		}
	}
	$params['active_tab'] = 'settings';
}

$tplvars = array(
//	'see' => $psee,
	'add' => $padd,
	'adm' => $padm,
	'bmod' => $bmod,
	'del' => $pdel,
	'mod' => $mod, //not $pmod
);

$baseurl = $this->GetModuleURLPath();

if ($pset) {
	if (isset($params['active_tab']))
		$showtab = $params['active_tab'];
	else
		$showtab = 'items'; //default
	$seetab1 = ($showtab=='items');
	$seetab2 = ($showtab=='settings');

	$tplvars['tab_headers'] = $this->StartTabHeaders().
		$this->SetTabHeader('items',$this->Lang('title_items'),$seetab1).
		$this->SetTabHeader('settings',$this->Lang('settings'),$seetab2).
		$this->EndTabHeaders().
		$this->StartTabContent();
} else {
	$tplvars['tab_headers'] = $this->StartTabHeaders().
		$this->SetTabHeader('items',$this->Lang('title_items'),TRUE).
		$this->EndTabHeaders().
		$this->StartTabContent();
}
$tplvars['tab_footers'] = $this->EndTabContent();
$tplvars['end_tab'] = $this->EndTab();
$tplvars['endform'] = $this->CreateFormEnd();

$utils = new Auther\Utils();
//$resume = json_encode(array($params['action'])); //head of resumption Q
$jsfuncs = array(); //script accumulators
$jsloads = array();
$jsincs = array();

//CONTEXTS TAB
$tplvars['startform1'] = $this->CreateFormStart($id,'processitem',$returnid,
	'POST','','','',array('active_tab'=>'items','resume'=>$resume));
$tplvars['start_items_tab'] = $this->StartTab('items');

//SETTINGS TAB
if ($pset) {
	$tplvars['startform2'] = $this->CreateFormStart($id,'defaultadmin',$returnid,
		'POST','','','',array('active_tab'=>'settings','resume'=>$resume));
	$tplvars['start_settings_tab'] = $this->StartTab('settings');

	$keys = array(
		'masterpass', 2, 2, 1,

		'attack_mitigation_time', 1,,,
		'attempts_before_ban', 1,,,
		'attempts_before_verify', 1,,,
		'bcrypt_cost', 1,,,
		'context_sender', 1,,,
		'context_email', 1,,,
		'cookie_domain', 1,,,
		'cookie_forget', 1,,,
		'cookie_http', 0, 0, 0, 0,
		'cookie_name', 1,,,
		'cookie_path', 1,,,
		'cookie_remember', 1,,,
		'cookie_secure', 0, 0, 0,

		'login_max_length', 1,,,
		'login_min_length', 1,,,
		'login_use_banlist', 0, 0, 0,

		'mail_charset', 1,,,
		'password_min_length', 1,,,
		'password_min_score', 1,,,
		'request_key_expiration', 1,,,

		'suppress_email_sender', 0, 0, 0,
		'suppress_activation_message', 0, 0, 0,
		'suppress_reset_message', 0, 0, 0,
	);

	$settings = array();

	$c = count($keys);
	for ($i = 0; $i < $c; $i+=3) {
		$kn = $keys[$i];
		$one = new stdClass();
		$one->title = $this->Lang('title_'.$kn);
		switch ($keys[$i+1]) {
		 case 0:
			$one->input = $this->CreateInputHidden($id, 'pref_'.$kn, 0).
				$this->CreateInputCheckbox($id, 'pref_'.$kn, $this->GetPreference($kn, 0));
			$one->must = 0;
			break;
		 case 1:
			$l = $keys[$i+2];
			$one->input = $this->CreateInputText($id, 'pref_'.$kn,
				$this->GetPreference($kn, ''), $l, $l);
			$one->must = ($keys[$i+3] > 0);
			break;
		 case 2:
			$l = $keys[$i+2];
			$one->input = $this->CreateTextArea(FALSE, $id,
				$this->GetPreference($kn, ''), 'pref_'.$kn, '', '', '', 50, $l);
			$one->must = ($keys[$i+3] > 0);
			break;
		}
		$one->help = langval($this, 'help_'.$kn, NULL);
		$settings[] = $one;
	}
} //$pset

$jsall = NULL;
$utils->MergeJS($jsincs,$jsfuncs,$jsloads,$jsall);
unset($jsincs);
unset($jsfuncs);
unset($jsloads);

echo Auther\Utils::ProcessTemplate($this,'adminpanel.tpl',$tplvars);
//inject constructed js after other content (pity we can't get to </body> or </html> from here)
if ($jsall)
	echo $jsall;
