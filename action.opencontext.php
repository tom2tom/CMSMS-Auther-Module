<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$cid = (int)$params['item_id']; //-1 for new context
$mod = ($cid == -1 || !empty($params['edit']));
$pmod = $this->_CheckAccess('admin');
$pown = $this->_CheckAccess('context');
if ($mod && !($pmod || $pown)) {
	exit;
}
$pmod = $pmod || $pown;

if (!function_exists('getContextProperties')) {
 function getContextProperties()
 {
	//for each set: 0=nane, 1=input-type, 2=text-input-size (length or rows), 3=compulsory
	//text-lengths here must conform to field lengths in module_auth_contexts table
	//see also: getModulePrefs()
	return [
	'name',					1, 50, 1,
	'alias',				1, 16, 0,
	'owner',				4, 50, 0,

	'security_level',		1, 3, 1,

	'login_max_length',		1, 3, 0,
	'login_min_length',		1, 3, 0,

	'password_min_length',	1, 3, 1,
	'password_min_score',	1, 3, 1,
	'default_password',		4, 50, 1,

	'name_required',		0, 0, 0,	
	'address_required',		0, 0, 0,
	'email_required',		0, 0, 0,
	'email_banlist',		0, 0, 0,
	'forget_rescue',		0, 0, 0,

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
	$props = getContextProperties();
	$c = count($props);
	for ($i = 0; $i < $c; $i += 4) {
		$kn = $props[$i];
		if (isset($params[$kn])) {
			if ($props[$i+1] === 0) { //boolean property
				$keys[] = $kn;
				$args[] = 1;
			} else {
				$val = $params[$kn];
				if ($props[$i+3] > 0) {
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
						$t = strtolower(preg_replace(['/\s+/', '/__+/'], ['_', '_'], $params['name']));
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
				 case 'default_password':
					$funcs = new Auther\Auth($this, $cid); //TODO if == -1
					if (!$funcs->validatePassword($val)) {
						//TODO abort, message
					} else {
						$cfuncs = new Auther\Crypter();
						$t = $cfuncs->decrypt_preference($this, 'masterpass');
						$val = $funcs->password_hash($val, $t);
					}
					break;
				 default:
					break;
				}
				$keys[] = $kn;
				$args[] = $val;
			}
		} elseif ($props[$i+1] === 0) {
			$keys[] = $kn;
			$args[] = 0;
		}
	}
	$pre = cms_db_prefix();
	if ($cid == -1) {
		$cid = $db->GenID($pre.'module_auth_contexts_seq');
		array_unshift($args, $cid);
		array_unshift($keys, 'id');
		$flds = implode(',',$keys);
		$fillers = str_repeat('?,',count($keys)-1);
		$sql = 'INSERT INTO '.$pre.'module_auth_contexts ('.$flds.') VALUES ('.$fillers.'?)';
	} else {
		$flds = implode('=?,',$keys);
		$args[] = $cid;
		$sql = 'UPDATE '.$pre.'module_auth_contexts SET '.$flds.'=? WHERE id=?';
	}
	$ares = $db->Execute($sql, $args);

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

$tplvars = ['mod' => $mod, 'own' => $pown];
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

if (!$mod) {
	$yes = $this->Lang('yes');
	$no = $this->Lang('no');
}

$options = [];
$props = getContextProperties();
$c = count($props);
for ($i = 0; $i < $c; $i += 4) {
	$kn = $props[$i];
	$one = new stdClass();
	$one->title = $this->Lang('title_'.$kn);
	switch ($props[$i+1]) {
	 case 0:
	 	if ($mod) {
			$one->input = $this->CreateInputCheckbox($id, $kn, 1, $data[$kn]);
		} else {
			$one->input = ($data[$kn]) ? $yes:$no;
		}
		$one->must = 0;
		break;
	 case 1:
	 	if ($mod) {
			$l = $props[$i+2];
			$one->input = $this->CreateInputText($id, $kn, $data[$kn], $l, $l);
			$one->must = ($props[$i+3] > 0);
		} else {
			$one->input = $data[$kn];
			$one->must = 0;
		}
		break;
/*	 case 2:
		$l = $props[$i+2];
		if ($mod) {
			$one->input = $this->CreateTextArea(FALSE, $id, $data[$kn], 'pref_'.$kn,
				'', '', '', 50, $l);
			$one->must = ($props[$i+3] > 0);
		} else {
			$one->input = $data[$kn];
			$one->must = 0;
		}
		break;
*/
	 case 4:
		switch ($kn) {
		 case 'owner':
			if (!$pown) {
				unset($one);
				break 2;
			} elseif ($mod) {
				$pre = cms_db_prefix();
		//cmsms function check_permission() returns FALSE for everyone other than
		//the current user, so we replicate its backend operation here
				$sql = 'SELECT DISTINCT U.user_id,U.first_name,U.last_name FROM '.$pre.'users U
JOIN '.$pre.'user_groups UG ON U.user_id = UG.user_id
JOIN '.$pre.'group_perms GP ON GP.group_id = UG.group_id
JOIN '.$pre.'permissions P ON P.permission_id = GP.permission_id
JOIN '.$pre.'groups GR ON GR.group_id = UG.group_id
WHERE U.admin_access=1 AND U.active=1 AND GR.active=1 AND P.permission_name IN ("AuthModuleAdmin","AuthModifyContext")
ORDER BY U.last_name,U.first_name';
				$allusers = $db->GetAssoc($sql);
				if ($allusers) {
					$choices = [$this->Lang('allpermitted')=>0];
					foreach ($allusers as $uid=>$row) {
						$t = trim($row['first_name'].' '.$row['last_name']);
						$choices[$t] = $uid;
					}
				} else {
					$choices = [$this->Lang('notpermitted')=>-1];
				}
				$one->input = $this->CreateInputDropdown($id, $kn, $choices, -2, $data[$kn]);
			} else {
				if ($data[$kn]) {
					if ($data[$kn] != -1) {
						$pre = cms_db_prefix();
						$sql = 'SELECT first_name,last_name FROM '.$pre.'users WHERE user_id=? AND active=1';
						$row = $db->GetRow($sql, [$data[$kn]]);
						if ($row) {
							$t = trim($row['first_name'].' '.$row['last_name']);
						} else {
							$t = $this->Lang('notpermitted');
						}
					} else {
						$t = $this->Lang('notpermitted');
					}
				} else {
					$t = $this->Lang('allpermitted');
				}
				$one->input = $t;
			}
			$one->must = 0;
			break;
		 case 'default_password':
			if ($mod) {
				if ($data[$kn]) {
					$funcs = new Auther\Crypter();
					$t = $funcs->decrypt_preference($this, 'masterpass');
					$funcs = new Auther\Auth($this, $cid); //TODO if == -1
					$val = $funcs->password_retrieve($data[$kn], $t);
				} else {
					$val = '';
				}
				$l = $props[$i+2];
				$one->input = $this->CreateInputText($id, $kn, $val, $l, $l);
				$one->must = ($props[$i+3] > 0);

				$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/jquery-inputCloak.min.js"></script>
EOS;
				$jsloads[] = <<<EOS
 $('#{$id}{$kn}').inputCloak({
  type:'see4',
  symbol:'\u25CF'
 });
EOS;
			} else {
				$one->input = ''; //TODO $this->Lang('private');
				$one->must = 0;
			}
			break;
		} //switch($kn)
		break;
	}
	$kn = 'help_'.$kn;
	if (langhasval($this, $kn)) {
		$one->help = $this->Lang($kn);
	}
	$options[] = $one;
}

$tplvars['options'] = $options;
if ($mod) {
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
