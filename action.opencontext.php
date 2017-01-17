<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$cid = (int)$params['item_id']; //-1 for new context
$pmod = ($cid == -1 || !empty($params['edit']));
if ($pmod && !($this->_CheckAccess('admin') || $this->_CheckAccess('context'))) {
	exit;
}

if (!function_exists('getContextProperties')) {
 function getContextProperties()
 {
	//for each set: 0=nane, 1=input-type, 2=text-input-size (length or rows), 3=compulsory
	//text-lengths here must conform to field lengths in module_auth_contexts table
	//see also: getModulePrefs()
	return [
	'name',					1, 50, 1,
	'alias',				1, 16, 0,

	'security_level',		1, 3, 1,

	'login_max_length',		1, 3, 0,
	'login_min_length',		1, 3, 0,

	'password_min_length',	1, 3, 1,
	'password_min_score',	1, 3, 1,

	'address_required',		0, 0, 0,
	'email_required',		0, 0, 0,
	'email_banlist',		0, 0, 0,

	'attempts_before_verify',1, 3, 0,
	'attempts_before_ban',	1, 3, 0,
	'attack_mitigation_span',1, 16, 0,
	'request_key_expiration',1, 16, 1,

	'send_activate_message',0, 0, 0,
	'send_reset_message',	0, 0, 0,
	'context_sender',		1, 50, 0,
	'context_address',		1, 50, 0,
	'message_charset',		1, 16, 0,

	'cookie_name',			1, 32, 1,
//	'cookie_domain',		1, 48, 1,
//	'cookie_path',			1, 48, 1,
//	'cookie_http',			0, 0, 0,
//	'cookie_secure',		0, 0, 0,
	'cookie_remember',		1, 16, 1,
	'cookie_forget',		1, 16, 1,
	];
 }
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
	$this->Redirect($id, 'defaultadmin');
} elseif (isset($params['submit'])) {
	$keys = [];
	$args = [];
	$keys = getContextProperties();
	$c = count($keys);
	for ($i = 0; $i < $c; $i += 4) {
		$kn = $keys[$i];
		if (isset($params[$kn])) {
			if ($keys[$i+1] === 0) { //boolean property
				$keys[] = $kn;
				$args[] = 1;
			} else {
				$val = $params[$kn];
				if ($keys[$i+3] > 0) {
					if (!($val || is_numeric($val))) {
						//TODO abort, message
					}
				}
				if (is_numeric($val)) {
					$val += 0;
				}
//TODO validate, process
				switch ($kn) {
				 case 'alias':
					if (!$val) {
						$t = strtolower(preg_replace(array('/\s+/', '/__+/'), array('_', '_'), $data['name']));
						$val = substr($t, 0, 16); //NB no check for alias duplication
					}
					break;
				 case 'attack_mitigation_span':
				 case 'request_key_expiration':
				 case 'cookie_remember':
				 case 'cookie_forget':
				 	if (empty($dt)) {
						$dt = new DateTime('@0', NULL);
					}
					$lvl = error_reporting(0);
					$dt = $dt->modify('+'.$val);
					error_reporting($lvl);
					if (!$dt) {
						//TODO abort, message
					}
					break;
				 case 'security_level':
					if ($val < Auther::NOBOT || $val > Auther::HISEC) {
						//TODO abort, message
					}
					break;
				 case 'password_min_score':
					if ($val < 1 || $val > 5) {
						//TODO abort, message
					}
					break;
				 default:
					break;
				}
				$keys[] = $kn;
				$args[] = $val;
			}
		} elseif ($keys[$i+1] === 0) {
			$keys[] = $kn;
			$args[] = 0;
		}
	}
	$pre = cms_db_prefix();
	if ($cid == -1) {
		$cid = $db->GenId($pre.'module_auth_contexts_seq');
		array_shift($args, $cid);
		array_shift($keys, 'id');
		$flds = implode(',',$keys);
		$fillers = str_repeat('?,',count($keys)-1);
		$sql = 'INSERT INTO '.$pre.'module_auth_contexts ('.$flds.') VALUES ('.$fillers.'?)';
	} else {
		$flds = implode('=?',$keys);
		$args[] = $cid;
		$sql = 'UPDATE '.$pre.'module_auth_contexts SET '.$flds.'=? WHERE id=?';
	}
	$db->Execute($sql, $args);

	$this->Redirect($id, 'defaultadmin');
}

if ($cid > -1) { //existing data
	$pre = cms_db_prefix();
	$sql = "SELECT * FROM {$pre}module_auth_contexts WHERE id=?";
	$data = $db->GetRow($sql,[$cid]);
} else {
	$data = [];
	$keys = getContextProperties();
	$c = count($keys);
	for ($i = 0; $i < $c; $i += 4) {
		$kn = $keys[$i];
		$data[$kn] = $this->GetPreference($kn);
	}
	if (!$data['name']) {
		$data['name'] = $this->Lang('missingname');
	}
}

$utils = new Auther\Utils();

$tplvars = ['mod' => $pmod];
$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = [
	'item_id'=>$cid,
	'edit'=>!empty($params['edit'])
]; //TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'opencontext',$returnid,'POST',
	'','','',$hidden);
$tplvars['endform'] = $this->CreateFormEnd();
if ($cid == -1) {
	$tplvars['title'] = $this->Lang('title_contextadd');
} else {
	$tplvars['title'] = $this->Lang('title_contextfull');
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
$keys = getContextProperties();
$c = count($keys);
for ($i = 0; $i < $c; $i += 4) {
	$kn = $keys[$i];
	$one = new stdClass();
	$one->title = $this->Lang('title_'.$kn);
	switch ($keys[$i+1]) {
	 case 0:
	 	if ($pmod) {
			$one->input = $this->CreateInputCheckbox($id, $kn, 1, $data[$kn]);
		} else {
			$one->input = ($data[$kn]) ? $yes:$no;
		}
		$one->must = 0;
		break;
	 case 1:
	 	if ($pmod) {
			$l = $keys[$i+2];
			$one->input = $this->CreateInputText($id, $kn, $data[$kn], $l, $l);
			$one->must = ($keys[$i+3] > 0);
		} else {
			$one->input = $data[$kn];
			$one->must = 0;
		}
		break;
/*	 case 2:
		$l = $keys[$i+2];
		if ($pmod) {
			$one->input = $this->CreateTextArea(FALSE, $id, $data[$kn], 'pref_'.$kn,
				'', '', '', 50, $l);
			$one->must = ($keys[$i+3] > 0);
		} else {
			$one->input = $data[$kn];
			$one->must = 0;
		}
		break;
*/
	}
	$kn = 'help_'.$kn;
	if (langhasval($this, $kn)) {
		$one->help = $this->Lang($kn);
	}
	$options[] = $one;
}

$tplvars['options'] = $options;
if ($pmod) {
	$jsloads[] = <<<EOS
$('[name="{$id}send_activate_message"],[name="{$id}send_reset_message"]').change(function() {
 if (this.checked) {
  $('[name="{$id}address_required"],[name="{$id}email_required"]').prop('checked',true);
 }
});
EOS;
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
