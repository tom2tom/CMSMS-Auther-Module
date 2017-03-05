<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$cid = (int)$params['ctx_id']; //-1 for new context
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

	'security_level',		4, 0, 0,

	'login_min_length',		1, 3, 0,
	'login_max_length',		1, 3, 0,
	'email_login',			0, 0, 0,

	'password_min_length',	1, 3, 1,
	'password_min_score',	1, 3, 1,
	'default_password',		4, 50, 1,
	'password_rescue',		0, 0, 0,

	'name_required',		0, 0, 0,
	'address_required',		0, 0, 0,
	'email_required',		0, 0, 0,
	'email_banlist',		0, 0, 0,

	'raise_count',			1, 3, 0,
	'ban_count',			1, 3, 0,
	'attack_mitigation_span',1, 16, 0,
	'request_key_expiration',1, 16, 1,

	'context_site',			1, 40, 1,
	'context_sender',		1, 40, 0,
	'context_address',		1, 60, 0,
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

if (isset($params['cancel'])) {
	$this->Redirect($id, 'defaultadmin');
} elseif (isset($params['submit'])) {
	$keys = [];
	$args = [];
	$msg = FALSE;

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
				if (is_numeric($val)) {
					$val += 0;
				} else {
					$val = trim($val);
					if (!$val && $props[$i+3] > 0) {
						$msg = $this->Lang('missing_type',$this->Lang('title_'.$kn));
						break;
					}
				}
//TODO validate, process
				switch ($kn) {
				 case 'alias':
					if (!$val) {
						$t = preg_replace(['/\s+/', '/__+/'], ['_', '_'], $params['name']);
						if (extension_loaded('mbstring')) {
							$t = mb_convert_case($t, MB_CASE_LOWER, 'UTF-8');
						} else {
							$t = strtolower($t);
						}
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
						$msg = $this->Lang('invalid_type',$this->Lang('title_'.$kn));
						break 2;
					}
					break;
				 case 'security_level':
					if ($val < Auther::NOBOT || $val > Auther::HISEC) {
						$msg = $this->Lang('invalid_type',$this->Lang('title_'.$kn));
						break 2;
					}
					break;
				 case 'password_min_score':
					if ($val < 1 || $val > 5) {
						$msg = $this->Lang('invalid_type',$this->Lang('title_'.$kn));
						break 2;
					}
					break;
				 case 'default_password':
				 	$t = ($cid == -1) ? 0:$cid;
					$funcs = new Auther\Auth($this, $t);
					$status = $funcs->validatePassword($val);
					if ($status[0]) {
						$cfuncs = new Auther\Crypter($this);
						$val = $cfuncs->encrypt_value($val);
					} else {
						$msg = $status[1];
						break 2;
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

	if (!$msg) {
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
}

if (empty($msg)) {
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
			$data['name'] = $this->Lang('missing_name');
		}
		$data['default_password'] = ''; //will be recovered later
	}
} else {
	//after an error, retain supplied values
	$data = [];
	$keys = getContextProperties();
	$c = count($keys);
	for ($i = 0; $i < $c; $i += 4) {
		$kn = $keys[$i];
		$data[$kn] = (isset($params[$kn])) ? $params[$kn]:0;
	}
}

$utils = new Auther\Utils();

$tplvars = ['mod' => $mod, 'own' => $pown];
$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = [
	'ctx_id'=>$cid,
	'edit'=>!empty($params['edit'])
]; //TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'opencontext',$returnid,'POST',
	'','','',$hidden);
$tplvars['endform'] = $this->CreateFormEnd();
if (!empty($msg)) {
	$tplvars['message'] = $msg;
}
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
		 case 'security_level':
			$levels = [
				Auther::NOBOT => 'level_NOBOT',
				Auther::LOSEC => 'level_LOSEC',
				Auther::MIDSEC => 'level_MIDSEC',
				Auther::CHALLENGED => 'level_CHALLENGED',
				Auther::HISEC => 'level_HISEC'
			];
			if ($mod) {
				$choices = [];
				foreach ($levels as $l=>$key) {
					$t = $this->Lang($key);
					$choices[$t] = $l;
				}
				$one->input = $this->CreateInputDropdown($id, $kn, $choices, -1, $data[$kn]);

				$l1 = Auther::MIDSEC;
				$l2 = Auther::CHALLENGED;
				$jsloads[] = <<<EOS
 $('#{$id}security_level').change(function() {
  var lvl = this.value;
  if (lvl == {$l1} || lvl == {$l2}) {
   $('[name="{$id}address_required"],[name="{$id}email_login"]').prop('checked',true);
  }
 });
EOS;
			} else {
				$key = $levels[$data[$kn]];
				$one->input = $this->Lang($key);
			}
			$one->must = 0;
			break;
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
				$cfuncs = new Auther\Crypter($this);
				if ($data[$kn]) {
					$val = $cfuncs->decrypt_value($data[$kn]);
				} else {
					$val = $cfuncs->decrypt_preference('default_password');
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

	if (!isset($one->help)) {
		$t = $this->Lang('help_'.$kn);
		if (strpos($t, 'Missing Languagestring') === FALSE) {
			$one->help = $t;
		} else {
			$one->help = NULL;
		}
	}

	$options[] = $one;
}

$tplvars['options'] = $options;
if ($mod) {
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
