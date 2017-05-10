<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
if (!function_exists('getModulePrefs')) {
 function getModulePrefs()
 {
	//for each set: 0=name, 1=input-type, 2=text-input-size (length or rows), 3=compulsory
	//text-lengths here must conform to field lengths in module_auth_contexts table
	//see also: getContextProperties()
	return [
	'masterpass',				4, 2, 1,
	'security_level',			4, 0, 0,

	'login_min_length',			1, 3, 0,
	'login_max_length',			1, 3, 0,
	'email_login',				0, 0, 0,

	'password_min_length',		1, 3, 1,
	'password_min_score',		1, 3, 1,
	'password_forget',			1, 16, 0,
	'default_password',			4, 50, 1,
	'password_rescue',			0, 0, 0,

	'name_required',			0, 0, 0,
	'address_required',			0, 0, 0,
	'email_required',			0, 0, 0,

	'email_banlist',			0, 0, 0,
	'email_domains',			1, 60, 0,
	'email_subdomains',			1, 60, 0,
	'email_topdomains',			1, 60, 0,

	'raise_count',				1, 3, 0,
	'ban_count',				1, 3, 0,
	'attack_mitigation_span',	1, 16, 1,
	'request_key_expiration',	1, 16, 1,

	'context_site',				1, 40, 1,
	'context_sender',			1, 40, 0,
	'context_address',			1, 60, 0,
	'message_charset',			1, 16, 0,
	'sms_prefix',				1, 6, 1,

	'cookie_name',				1, 32, 1,
//	'cookie_domain',			1, 48, 1,
//	'cookie_path',				1, 48, 1,
//	'cookie_http',				0, 0, 0,
//	'cookie_secure',			0, 0, 0,
	'cookie_remember',			1, 16, 1,
	'cookie_forget',			1, 16, 1,

	'recaptcha_key',			1, 40, 0,
	'recaptcha_secret',			4, 40, 0,
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

$cfuncs = new Auther\Crypter($this);

if (isset($params['submit'])) {
	//save settings
	if (!$pset) {
		exit;
	}

	$msg = FALSE;
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
				} else {
					$val = trim($val);
				    if (!$val && $props[$i+3] > 0) {
						$msg = $this->Lang('missing_type',$this->Lang('title_'.$kn));
						break 2;
					}
				}
				switch ($kn) {
				 case 'password_forget':
					if (empty($val)) {
						break;
					}
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
					$oldpw = $cfuncs->decrypt_preference($kn);
					if ($oldpw != $val) {
/* TODO re-hash all relevant data
						$pref = cms_db_prefix();
						$sql = 'SELECT , FROM '.$pref.'module_';
						$rst = $db->Execute($sql);
						if ($rst) {
							$sql = 'UPDATE '.$pref.'module_ SET =? WHERE =?';
							while (!$rst->EOF) {
								$t = $cfuncs->decrypt_value($rst->fields[''], $oldpw);
								if ($newpw) {
									$t = $cfuncs->encrypt_value($t, $newpw);
								}
								$db->Execute($sql, [$t, $rst->fields['']]);
								if (!$rst->MoveNext()) {
									break;
								}
							}
							$rst->Close();
						}
*/
					}
					$cfuncs->encrypt_preference($kn, $val);
					continue 2;
				 case 'default_password':
					$afuncs = new Auther\Auth($this, NULL);
					$status = $afuncs->ValidatePassword($val);
					if ($status[0]) {
						$cfuncs->encrypt_preference($kn, $val);
						continue 2;
					} else {
						$msg = $status[1];
						break 2;
					}
				 case 'recaptcha_secret':
					$cfuncs->encrypt_preference($kn, $val);
					continue 2;
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
} elseif (isset($params['import'])) {
	if (!$pmod) {
		exit;
	}
	$this->Redirect($id, 'import', '', ['resume'=>'defaultadmin']);
}


$tplvars = [
	'mod' => $pmod,
	'see' => $psee,
	'set' => $pset
];

if (isset($params['active_tab'])) {
	$showtab = $params['active_tab'];
} else {
	$showtab = 'items'; //default
}
$seetab1 = ($showtab=='items');
$seetab2 = ($showtab=='challenges');

if ($pset) {
	$seetab3 = ($showtab=='settings');

	$t = $this->StartTabHeaders().
		$this->SetTabHeader('items',$this->Lang('title_contexts'),$seetab1).
		$this->SetTabHeader('challenges',$this->Lang('title_challenges'),$seetab2).
		$this->SetTabHeader('settings',$this->Lang('title_settings'),$seetab3).
		$this->EndTabHeaders().
		$this->StartTabContent();
} else {
	$t = $this->StartTabHeaders().
		$this->SetTabHeader('items',$this->Lang('title_items'),$seetab1).
		$this->SetTabHeader('challenges',$this->Lang('title_challenges'),$seetab2).
		$this->EndTabHeaders().
		$this->StartTabContent();
}

//workaround CMSMS2 crap 'auto-end', EndTab() & EndTabContent() before [1st] StartTab()
$tplvars += array(
	'tab_headers' => $t,
	'end_tab' => $this->EndTab(),
	'tab_footers' => $this->EndTabContent(),
	'endform' => $this->CreateFormEnd()
);

if (!empty($msg)) {
	$tplvars['message'] = $msg;
} elseif (!empty($params['message'])) {
	$tplvars['message'] = $params['message'];
}

$utils = new Auther\Utils();

$jsfuncs = []; //script accumulators
$jsloads = [];
$jsincs = [];
$baseurl = $this->GetModuleURLPath();

//CONTEXTS TAB
$tplvars['start_items_tab'] = $this->StartTab('items');
$tplvars['startform1'] = $this->CreateFormStart($id, 'defaultadmin', $returnid);

$theme = ($this->before20) ? cmsms()->get_variable('admintheme'):
	cms_utils::get_theme_object();

if (empty($msg)) {
	$pre = cms_db_prefix();
	$sql = <<<EOS
SELECT C.id,C.name,C.alias,C.owner,COUNT(U.context_id) AS users
FROM {$pre}module_auth_contexts C
LEFT JOIN {$pre}module_auth_users U ON C.id = U.context_id
GROUP BY C.id
EOS;
	$data = $db->GetArray($sql);
} else {
	//after an error, retain supplied values
	$data = [];
	$props = getModulePrefs();
	$c = count($props);
	for ($i = 0; $i < $c; $i += 4) {
		$kn = $props[$i];
		$data[$kn] = (isset($params[$kn])) ? $params[$kn]:0;
	}
}

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

	$uid = ($pmod) ? 0 : get_userid(FALSE); //current user

	$rows = [];
	foreach ($data as &$one) {
		if ($uid == 0 || $uid == $one['owner']) {
			$cid = (int)$one['id'];
			$oneset = new stdClass();
			if ($pmod) {
				$oneset->name = $this->CreateLink($id,'opencontext','',$one['name'],
					['ctx_id'=>$cid,'edit'=>1]);
			} else {
				$oneset->name = $one['name'];
			}
			$oneset->alias = $one['alias'];
			$oneset->id = $cid;
			$oneset->count = $one['users'];
			$oneset->users = $this->CreateLink($id,'users','',$icon_user,
				['ctx_id'=>$cid]);
			$oneset->see = $this->CreateLink($id,'opencontext','',$icon_see,
				['ctx_id'=>$cid, 'edit'=>0]);
			if ($pmod) {
				$oneset->edit = $this->CreateLink($id,'opencontext','',$icon_edit,
					['ctx_id'=>$cid,'edit'=>1]);
				if ($cid > 0) {
					$oneset->del = $this->CreateLink($id,'deletecontext','',$icon_delete,
						['ctx_id'=>$cid]);
					$oneset->sel = $this->CreateInputCheckbox($id,'sel[]',$cid,-1);
				} else {
					$oneset->del = NULL;
					$oneset->sel = NULL;
				}
			}
			$rows[] = $oneset;
		}
	}
	unset($one);

	$tplvars['items'] = $rows;
	$tplvars['icount'] = count($rows);

	if ($pmod) {
		$tplvars['delete'] = $this->CreateInputSubmit($id,'delete',$this->Lang('delete'),
			'title="'.$this->Lang('tip_delcontext').'"');
		$tplvars['import'] = $this->CreateInputSubmit($id,'import',$this->Lang('import'),
			'title="'.$this->Lang('tip_importuser').'"');

		$jsfuncs[] = <<<EOS
function any_selected() {
 var cb = $('#itemstable input[name="{$id}sel[]"]:checked');
 return (cb.length > 0);
}
EOS;
		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/lib/js/jquery.alertable.min.js"></script>
EOS;
		$t = $this->Lang('confirm_delsel');
		$jsloads[] = <<<EOS
 $('#itemacts #{$id}delete').click(function() {
  if (any_selected()) {
   var tg = this;
   $.alertable.confirm('$t', {
    okName: '{$this->Lang('proceed')}',
    cancelName: '{$this->Lang('cancel')}'
   }).then(function() {
    $(tg).trigger('click.deferred');
   });
  }
  return false;
 });
EOS;
		$t = $this->Lang('confirm_del','%s');
		$jsloads[] = <<<EOS
 $('#itemstable .linkdel > a').click(function(ev) {
  var tg = ev.target,
   nm = $(this.parentNode).siblings(':first').children(':first').text(),
   msg = '$t'.replace('%s',nm);
  $.alertable.confirm(msg, {
    okName: '{$this->Lang('proceed')}',
    cancelName: '{$this->Lang('cancel')}'
  }).then(function() {
   $(tg).trigger('click.deferred');
  });
  return false;
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
		['ctx_id'=>-1,'edit'=>1]);
	$tplvars['textlinkadd'] = $this->CreateLink($id,'opencontext','',$t,
		['ctx_id'=>-1,'edit'=>1]);
}

//CHALLENGES TAB
$tplvars['start_challenges_tab'] = $this->StartTab('challenges');
$tplvars['startform2'] = $this->CreateFormStart($id, 'defaultadmin', $returnid);
//TODO content

//SETTINGS TAB
if ($pset) {
	$tplvars['start_settings_tab'] = $this->StartTab('settings');
	$tplvars['startform3'] = $this->CreateFormStart($id, 'defaultadmin', $returnid);
	$tplvars['compulsory'] = $this->Lang('compulsory_items');

	$settings = [];

	if (!isset($cfuncs)) {
		$cfuncs = new Auther\Crypter($this);
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
				$t = $cfuncs->decrypt_preference($kn);
				$one->input = $this->CreateTextArea(FALSE, $id, $t, $kn, 'cloaked',
					'', '', '', 40, $props[$i+2]);
				break;
			 case 'default_password':
			 case 'recaptcha_secret':
				$t = $cfuncs->decrypt_preference($kn);
				$l = $props[$i+2];
				$t = $this->CreateInputText($id, $kn, $t, $l, $l);
				$one->input = strtr($t, ['class="'=>'class="cloaked ']);
				break;
			 case 'security_level':
				$choices = [];
				$levels = [
					Auther::NOBOT => 'level_NOBOT',
					Auther::LOSEC => 'level_LOSEC',
					Auther::MIDSEC => 'level_MIDSEC',
					Auther::CHALLENGED => 'level_CHALLENGED',
					Auther::HISEC => 'level_HISEC'
				];
				foreach ($levels as $l=>$key) {
					$t = $this->Lang($key);
					$choices[$t] = $l;
				}
				$t = $this->GetPreference($kn, Auther::LOSEC);
				$one->input = $this->CreateInputDropdown($id, $kn, $choices, -1, $t);
				break;
			}
			$one->must = ($props[$i+3] > 0);
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

		$settings[] = $one;
	}

	$tplvars['settings'] = $settings;

	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/lib/js/jquery-inputCloak.min.js"></script>
EOS;
	$l1 = Auther::MIDSEC;
	$l2 = Auther::CHALLENGED;
	$jsloads[] = <<<EOS
 $('.cloaked').inputCloak({
  type:'see4',
  symbol:'\u25CF'
 });
 $('#{$id}security_level').change(function() {
  var lvl = this.value;
  if (lvl == {$l1} || lvl == {$l2}) {
   $('[name="{$id}address_required"],[name="{$id}email_login"]').prop('checked',true);
  }
 });
EOS;

	$tplvars['submit'] = $this->CreateInputSubmit($id,'submit',$this->Lang('submit'));
	$tplvars['cancel'] = $this->CreateInputSubmit($id,'cancel',$this->Lang('cancel'));
} //$pset

//DEBUG
$funcs = new Auther\Setup();
$token = FALSE;
list($authhtm,$authjs) = $funcs->GetPanel(1, 'change', ['Auther','dummy',$id], TRUE, $token);
$tplvars['authform'] = $authhtm;
//$tplvars['authform'] = NULL;

$jsall = $utils->MergeJS($jsincs, $jsfuncs, $jsloads);
unset($jsincs);
unset($jsfuncs);
unset($jsloads);

echo $utils->ProcessTemplate($this, 'adminpanel.tpl', $tplvars);
if ($jsall) {
	echo $jsall; //inject constructed js after other content
}
if ($authjs) {
	echo $authjs;
}
