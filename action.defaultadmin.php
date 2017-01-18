<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

if (!function_exists('langhasval')) {
 function langhasval(&$mod, $key)
 {
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
if (!function_exists('getModulePrefs')) {
 function getModulePrefs()
 {
	//for each set: 0=name, 1=input-type, 2=text-input-size (length or rows), 3=compulsory
	//text-lengths here must conform to field lengths in module_auth_contexts table
	//see also: getContextProperties()
	return [
	'masterpass',				4, 2, 1,
	'security_level',			1, 3, 1,

	'login_max_length',			1, 3, 0,
	'login_min_length',			1, 3, 0,

	'password_min_length',		1, 3, 1,
	'password_min_score',		1, 3, 1,
	'default_password',			4, 50, 1,

	'address_required',			0, 0, 0,
	'email_required',			0, 0, 0,
	'email_banlist',			0, 0, 0,
	'forget_rescue',			0, 0, 0,

	'attempts_before_verify',	1, 3, 0,
	'attempts_before_ban',		1, 3, 0,
	'attack_mitigation_span',	1, 16, 0,
	'request_key_expiration',	1, 16, 1,

	'send_activate_message',	0, 0, 0,
	'send_reset_message',		0, 0, 0,
	'context_sender',			1, 50, 0,
	'context_address',			1, 50, 0,
	'message_charset',			1, 16, 0,

	'cookie_name',				1, 32, 1,
//	'cookie_domain',			1, 48, 1,
//	'cookie_path',				1, 48, 1,
//	'cookie_http',				0, 0, 0,
//	'cookie_secure',			0, 0, 0,
	'cookie_remember',			1, 16, 1,
	'cookie_forget',			1, 16, 1,
	];
 }
}

$pmod = $this->_CheckAccess('admin');
if ($pmod) {
	$psee = TRUE;
	$pset = TRUE;
} else {
	$psee = $this->_CheckAccess('view');
	$pset = FALSE;
}

$cfuncs = new Auther\Crypter();

if (isset($params['submit'])) {
	//save settings
	if (!$pset) {
		exit;
	}

	$props = getModulePrefs();
	$c = count($props);
	for ($i = 0; $i < $c; $i += 4) {
		$kn = $props[$i];
		if (isset($params[$kn])) {
			if ($props[$i+1] === 0) { //boolean property
				$this->SetPreference($kn, 1);
			} else {
				$val = $params[$kn];
				if (is_numeric($val)) {
					$val += 0;
				}
//TODO validate, process
				switch ($kn) {
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
						break 2;
					}
					break;
				 case 'security_level':
					if ($val < Auther::NOBOT) {
						$val = Auther::NOBOT;
					} elseif ($val > Auther::HISEC) {
						$val = Auther::HISEC;
					}
					break;
				 case 'password_min_score':
					if ($val < 1) {
						$val = 1;
					} elseif ($val > 5) {
						$val = 5;
					}
					break;
				 case 'masterpass':
					if ($props[$i+3] > 0) {
						if (!$val) {
	//TODO abort, message
							break 2;
						}
					}
					$oldpw = $cfuncs->decrypt_preference($this, $kn);
					if ($oldpw != $val) {
	//TODO re-hash all relevant data
					}
					$cfuncs->encrypt_preference($this, $kn, $val);
					break 2;
				 case 'default_password':
					if ($props[$i+3] > 0) {
						$afuncs = new Auther\Auth($this, NULL);
						if (!$afuncs->validatePassword($val)) {
							//TODO abort, message
							break 2;
						}
					}
					$cfuncs->encrypt_preference($this, $kn, $val);
					break 2;
				 default:
					break;
				}
				$this->SetPreference($kn, $val);
			}
		} elseif ($props[$i+1] === 0) {
			$this->SetPreference($kn, 0);
		}
	}
	$params['active_tab'] = 'settings';
} elseif (isset($params['delete'])) {
	if (!$pmod) {
		exit;
	}
	if (isset($params['sel'])) {
		$utils = new Auther\Utils();
		$utils->DeleteContext($params['sel']);
	}
	$params['active_tab'] = 'items';
}

$tplvars = [
	'mod' => $pmod,
	'see' => $psee,
	'set' => $pset
];

if ($pset) {
	if (isset($params['active_tab']))
		$showtab = $params['active_tab'];
	else
		$showtab = 'items'; //default
	$seetab1 = ($showtab=='items');
	$seetab2 = ($showtab=='settings');

	$tplvars['tab_headers'] = $this->StartTabHeaders().
		$this->SetTabHeader('items',$this->Lang('title_contexts'),$seetab1).
		$this->SetTabHeader('settings',$this->Lang('title_settings'),$seetab2).
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

if (!empty($msg)) {
	$tplvars['message'] = $msg;
}

$utils = new Auther\Utils();
$baseurl = $this->GetModuleURLPath();

$jsfuncs = []; //script accumulators
$jsloads = [];
$jsincs = [];

//CONTEXTS TAB
$tplvars['start_items_tab'] = $this->StartTab('items');
$tplvars['startform1'] = $this->CreateFormStart($id, 'defaultadmin', $returnid);

$theme = ($this->before20) ? cmsms()->get_variable('admintheme'):
	cms_utils::get_theme_object();

$pre = cms_db_prefix();
$sql = <<<EOS
SELECT C.id,C.name,C.alias,COUNT(U.context) AS users
FROM {$pre}module_auth_contexts C
LEFT JOIN {$pre}module_auth_users U ON C.id = U.context
GROUP BY U.context
EOS;
$data = $db->GetArray($sql);

if ($data) {
	$tplvars['title_name'] = $this->Lang('title_name');
	$tplvars['title_alias'] = $this->Lang('title_alias');
	$tplvars['title_id'] = $this->Lang('title_id');
	$tplvars['title_users'] = $this->Lang('users');

	if ($pmod) {
		$t = $this->Lang('tip_usersedit');
	} else {
		$t = $this->Lang('tip_users');
	}
	$icon_user = '<img src="'.$baseurl.'/images/users.png" alt="'.$t.'" title="'.$t.'" border="0" />';
	$icon_see = $theme->DisplayImage('icons/system/view.gif',$this->Lang('tip_view'),'','','systemicon');
	if ($pmod) {
		$icon_edit = $theme->DisplayImage('icons/system/edit.gif',$this->Lang('tip_edit'),'','','systemicon');
		$icon_delete = $theme->DisplayImage('icons/system/delete.gif',$this->Lang('tip_delete'),'','','systemicon');
	}

	$rows = [];
	foreach ($data as &$one) {
		$cid = (int)$one['id'];
		$oneset = new stdClass();
		$oneset->name = $one['name'];
		$oneset->alias = $one['alias'];
		$oneset->id = $cid;
		$oneset->count = $one['users'];
		$oneset->users = $this->CreateLink($id,'users','',$icon_user,
			['item_id'=>$cid]);
		$oneset->see = $this->CreateLink($id,'opencontext','',$icon_see,
			['item_id'=>$cid, 'edit'=>0]);
		if ($pmod) {
			$oneset->edit = $this->CreateLink($id,'opencontext','',$icon_edit,
				['item_id'=>$cid,'edit'=>1]);
			$oneset->del = $this->CreateLink($id,'deletecontext','',$icon_delete,
				['item_id'=>$cid]);
			$oneset->sel = $this->CreateInputCheckbox($id,'sel[]',$cid,-1);
		}
		$rows[] = $oneset;
	}
	unset($one);

	$tplvars['items'] = $rows;
	$tplvars['icount'] = count($rows);

	if ($pmod) {
		$tplvars['delbtn'] = $this->CreateInputSubmit($id,'delete',$this->Lang('delete'),
			'title="'.$this->Lang('tip_delcontext').'"');

		$jsfuncs[] = <<<EOS
function any_selected() {
 var cb = $('#itemstable input[name="{$id}sel[]"]:checked');
 return (cb.length > 0);
}
EOS;
		$t = $this->Lang('confirm_delsel');
		$jsloads[] = <<<EOS
 $('#itemacts #{$id}delete').click(function() {
  if (any_selected()) {
   return confirm('$t');
  } else {
   return false;
  }
 });
EOS;
		$t = $this->Lang('confirm_del','%s');
		$jsloads[] = <<<EOS
 $('#itemstable .linkdel > a').click(function() {
  var nm = $(this.parentNode).siblings(':first').children(':first').text();
  return confirm('$t'.replace('%s',nm));
 });
EOS;
	} //$pmod
} else { //no data
	$tplvars['noitems'] = $this->Lang('nocontext');
	$tplvars['icount'] = 0;
}

if ($pmod) {
	$t = $this->Lang('addcontext');
	$icon_add = $theme->DisplayImage('icons/system/newobject.gif',$t,'','','systemicon');
	$tplvars['iconlinkadd'] = $this->CreateLink($id,'opencontext','',$icon_add,
		['item_id'=>-1,'edit'=>1]);
	$tplvars['textlinkadd'] = $this->CreateLink($id,'opencontext','',$t,
		['item_id'=>-1,'edit'=>1]);
}

//SETTINGS TAB
if ($pset) {
	$tplvars['start_settings_tab'] = $this->StartTab('settings');
	$tplvars['startform2'] = $this->CreateFormStart($id, 'defaultadmin', $returnid);
	$tplvars['compulsory'] = $this->Lang('compulsory_items');

	$settings = [];

	if (!isset($cfuncs)) {
		$cfuncs = new Auther\Crypter();
	}

	$props = getModulePrefs();
	$c = count($props);
	for ($i = 0; $i < $c; $i += 4) {
		$kn = $props[$i];
		$one = new stdClass();
		$one->title = $this->Lang('title_'.$kn);
		switch ($props[$i+1]) {
		 case 0:
			$one->input = $this->CreateInputCheckbox($id, $kn, 1, $this->GetPreference($kn, 0));
			$one->must = 0;
			break;
		 case 1:
			$l = $props[$i+2];
			$one->input = $this->CreateInputText($id, $kn, $this->GetPreference($kn, ''), $l, $l);
			$one->must = ($props[$i+3] > 0);
			break;
/*		 case 2:
			$l = $props[$i+2];
			$one->input = $this->CreateTextArea(FALSE, $id,
				$this->GetPreference($kn, ''), $kn, '', '', '', 50, $l);
			$one->must = ($props[$i+3] > 0);
			break;
*/
		 case 4:
		 	switch($kn) {
			 case 'masterpass':
				$t = $cfuncs->decrypt_preference($this, $kn);
				$one->input = $this->CreateTextArea(FALSE, $id, $t, $kn, 'cloaked',
					'', '', '', 40, $props[$i+2]);
				break;
			 case 'default_password':
				$t = $cfuncs->decrypt_preference($this, $kn);
				$l = $props[$i+2];
				$t = $this->CreateInputText($id, $kn, $t, $l, $l);
				$one->input = str_replace('class="', 'class="cloaked ', $t);
				break;
			}
			$one->must = ($props[$i+3] > 0);
			break;
		}
		$kn = 'help_'.$kn;
		if (langhasval($this, $kn)) {
			$one->help = $this->Lang($kn);
		}
		$settings[] = $one;
	}

	$tplvars['settings'] = $settings;

	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/jquery-inputCloak.min.js"></script>
EOS;
	$jsloads[] = <<<EOS
 $('.cloaked').inputCloak({
  type:'see4',
  symbol:'\u25CF'
 });
 $('[name="{$id}send_activate_message"],[name="{$id}send_reset_message"]').change(function() {
  if (this.checked) {
   $('[name="{$id}address_required"],[name="{$id}email_required"]').prop('checked',true);
  }
 });
EOS;

	$tplvars['submit'] = $this->CreateInputSubmit($id,'submit',$this->Lang('submit'));
	$tplvars['cancel'] = $this->CreateInputSubmit($id,'cancel',$this->Lang('cancel'));
} //$pset

$jsall = $utils->MergeJS($jsincs, $jsfuncs, $jsloads);
unset($jsincs);
unset($jsfuncs);
unset($jsloads);

echo $utils->ProcessTemplate($this, 'adminpanel.tpl', $tplvars);
if ($jsall) {
	echo $jsall; //inject constructed js after other content
}
