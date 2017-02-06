<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$uid = (int)$params['usr_id']; //-1 for new user
$pmod = ($uid == -1 || !empty($params['edit']));
if ($pmod && !($this->_CheckAccess('admin') || $this->_CheckAccess('user'))) {
	exit;
}

if (!function_exists('GetUserProperties')) {
 function GetUserProperties () {
 	//each: tablefield, langsuffix, type, textlen, maxtextlen, compulsory
	return [
	'name',		'name',		2, 40, 48, 0,
	'nameswap',	'nameswap',	0, 0,  0,  0,
	'address',	'contact',	2, 40, 96, 0,
	'publicid',	'identifier',	1, 40, 96, 1,
	'privhash',	'password_new', 2, 40, 72, 0, //fake
	'privreset','password_reset', 0, 0,  0,  0,
	'active',	'active',	0, 0,  0,  0,
	];
	//unused: id, context, addwhen, lastuse
 }
}

if (isset($params['cancel'])) {
	$this->Redirect($id, 'users', '', ['ctx_id'=>$params['ctx_id']]); //TODO parms
} elseif (isset($params['submit'])) {
	$funcs = new Auther\Auth($this, $params['ctx_id']);
	$cfuncs = new Auther\Crypter();
	$t = $cfuncs->decrypt_preference($this, 'masterpass');
	$msg = FALSE;

	$props = GetUserProperties ();
	$c = count($props);
	for ($i = 0; $i < $c; $i += 6) {
		$kf = $props[$i];
		if (isset($params[$kf])) {
			if ($props[$i+2] === 0) { //boolean property
				$keys[] = $kf;
				$args[] = 1;
			} else {
				$val = $params[$kf];
				if (is_numeric($val)) {
					$val += 0;
				} else {
					$val = trim($val);
					if (!$val && $props[$i+5] > 0) { //TODO condition maybe func(context), changed at runtime
						$msg = $this->Lang('missing_type', $this->Lang('title_'.$props[$i+1]));
						break;
					}
				}

				switch ($kf) {
				 case 'name':
//					$val = X::SanitizeName($val); TODO cleanup whitespace etc
					$status = $funcs->validateName($val);
					if ($status[0]) {
						$val = $cfuncs->encrypt_value($this, $val, $t);
					} else {
						$msg = $this->Lang('invalid_type', $this->Lang('title_'.$props[$i+1]));
						break 2;
					}
					break;
				 case 'address':
					$status = $funcs->validateAddress($val);
					if ($status[0]) {
						$val = $cfuncs->encrypt_value($this, $val, $t);
					} else {
						$msg = $status[1];
						break 2;
					}
					break;
				 case 'publicid':
					$status = $funcs->validateLogin($val);
					if (!$status[0]) {
						$msg = $status[1];
						break 2;
					}
					break;
				 case 'privhash':
					if (!$val) {
						//no replacement password
						continue 2;
					} else {
						$status = $funcs->validatePassword($val);
						if ($status[0]) {
							$val = password_hash($val, PASSWORD_DEFAULT);
						} else {
							$msg = $status[1];
							break 2;
						}
					}
					break;
				 default:
					break;
				}
				$keys[] = $kf;
				$args[] = $val;
			}
		} elseif ($props[$i+2] === 0) {
			$keys[] = $kf;
			$args[] = 0;
		}
	}

	if (!$msg) {
		$pre = cms_db_prefix();
		if ($uid == -1) {
			$uid = $db->GenID($pre.'module_auth_users_seq');
			array_unshift($args, $uid);
			array_push($args, (int)$params['ctx_id'], time());
			array_unshift($keys, 'id');
			array_push($keys, 'context_id', 'addwhen');

			$flds = implode(',',$keys);
			$fillers = str_repeat('?,',count($keys)-1);
			$sql = 'INSERT INTO '.$pre.'module_auth_users ('.$flds.') VALUES ('.$fillers.'?)';
		} else {
			$flds = implode('=?,',$keys);
			$args[] = $uid;
			$sql = 'UPDATE '.$pre.'module_auth_users SET '.$flds.'=? WHERE id=?';
		}
		$ares = $db->Execute($sql, $args);

		$this->Redirect($id, 'users', '', ['ctx_id'=>$params['ctx_id']]);
	}
}

$utils = new Auther\Utils();

if (!is_numeric($params['ctx_id'])) {
	$params['ctx_id'] = $utils->ContextID($params['ctx_id']);
}

$cfuncs = new Auther\Crypter();
$pre = cms_db_prefix();

if (empty($msg)) {
	if ($uid > -1) { //existing data
		$sql = "SELECT * FROM {$pre}module_auth_users WHERE id=?";
		$data = $db->GetRow($sql,[$uid]);
//		unset($data['lastuse']);
	} else {
		$data = [
		'id' => -1,
		'name' => '',
		'nameswap' => 0,
		'address' => '',
		'publicid' => $this->Lang('missing_name'),
		'context_id' => $params['ctx_id'],
		'privhash' => '',
		'active' => 1,
		];
	}
} else {
	//after an error, retain supplied values
	$data = [];
	$props = GetUserProperties ();
	$c = count($props);
	for ($i = 0; $i < $c; $i += 6) {
		$kf = $props[$i];
		$data[$kf] = (isset($params[$kf])) ? $params[$kf]:0;
	}
}

$cdata = $db->GetRow('SELECT name,password_min_length,password_min_score,address_required,email_required,name_required FROM '.$pre.'module_auth_contexts WHERE id=?', [$data['context_id']]);

$tplvars = ['mod' => $pmod];
$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = [
	'ctx_id'=>$data['context_id'],
	'usr_id'=>$data['id'],
	'edit'=>!empty($params['edit'])
]; //TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'openuser',$returnid,'POST',
	'','','',$hidden);
$tplvars['endform'] = $this->CreateFormEnd();
if (!empty($msg)) {
	$tplvars['message'] = $msg;
}
if ($uid == -1) {
	$tplvars['title'] = $this->Lang('title_useradd');
	$tplvars['desc'] = $this->Lang('name_to', $cdata['name']);
} else {
	$tplvars['title'] = $this->Lang('title_userfull');
	$tplvars['desc'] = $this->Lang('name_for', $cdata['name']);
}
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

$props = getUserProperties();
$c = count($props);
for ($i = 0; $i < $c; $i += 6) {
	$kf = $props[$i];
	$val = $data[$kf];

	$kl = $props[$i+1];
	$one = new stdClass();
	$one->title = $this->Lang('title_'.$kl);
	if (!$pmod || $props[$i+2] == 0) {
		$one->must = 0;
	} else {
		$one->must = ($props[$i+5] > 0);
	}
	switch ($props[$i+2]) {
	 case 0:
		if ($pmod) {
			$one->input = $this->CreateInputCheckbox($id, $kf, 1, $val);
		} else {
			$one->input = ($val) ? $yes:$no;
		}
		break;
	 case 1:
		if ($pmod) {
			$one->input = $this->CreateInputText($id, $kf, $val, $props[$i+3], $props[$i+4]);
		} else {
			$one->input = $val;
		}
		break;
	 case 2:
		switch ($kf) {
		 case 'name':
		 case 'address':
			$val = $cfuncs->decrypt_value($this, $val);
			if ($pmod) {
				$one->input = $this->CreateInputText($id, $kf, $val, $props[$i+3], $props[$i+4]);
			} else {
				$one->input = $val;
			}
			break;
		 case 'privhash':
			if ($uid == -1) {
				$one->title = $this->Lang('password');
				$one->must = 1;
			}
			if ($pmod) {
				$one->input = $this->CreateInputText($id, $kf, '', $props[$i+3], $props[$i+4]);
				$short = (int)$cdata['password_min_length'];
				$score = (int)$cdata['password_min_score'];
				$one->help = $this->Lang('help_'.$kl, $short, $score);
				break;
			} else {
				break 3;
			}
		}
		break;
	}

	if (!isset($one->help)) {
		$t = $this->Lang('help_'.$kl);
		if (strpos($t, 'Missing Languagestring') === FALSE) {
			$one->help = $t;
		} else {
			$one->help = NULL;
		}
	}

	$options[$kf] = $one;
}

$options['name']->must = ($cdata['name_required'] > 0);
$options['publicid']->must = ($cdata['address_required'] > 0 || $cdata['email_required'] > 0);

if ($pmod) {
	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/mailcheck.js"></script>
<script type="text/javascript" src="{$baseurl}/include/levenshtein.min.js"></script>
<script type="text/javascript" src="{$baseurl}/include/jquery.alertable.min.js"></script>
EOS;

	function ConvertDomains($pref)
	{
		if (!$pref)
			return '';
		$parts = explode(',',$pref);
		foreach ($parts as &$one) {
			$one = '\''.trim($one).'\'';
		}
		unset($one);
		if (count($parts) > 1) {
			$parts = array_unique($parts);
			sort($parts, SORT_STRING);
		}
		return implode(',',$parts);
	}

	$pref = $this->GetPreference('email_topdomains');
	$topdomains = ConvertDomains($pref);
	if ($topdomains) {
		$topdomains = <<<EOS

   topLevelDomains: [$topdomains],
EOS;
	}
	$pref = $this->GetPreference('email_domains');
	$domains = ConvertDomains($pref);
	if ($domains) {
		$domains = <<<EOS

   domains: [$domains],
EOS;
	}
	$pref = $this->GetPreference('email_subdomains');
	$l2domains = ConvertDomains($pref);
	if ($l2domains) {
		$l2domains = <<<EOS

   secondLevelDomains: [$l2domains],
EOS;
	}

	$jsloads[] = <<<EOS
 $('#{$id}address,#{$id}publicid').blur(function() {
  $(this).mailcheck({{$domains}{$l2domains}{$topdomains}
   distanceFunction: function(string1,string2) {
    var lv = Levenshtein;
    return lv.get(string1,string2);
   },
   suggested: function(element,suggest) {
    var msg = '{$this->Lang('meaning_type','%s')}'.replace('%s','<strong>'+suggest.full+'</strong>');
	$.alertable.confirm(msg, {
	 html: true,
     okName: '{$this->Lang('yes')}',
     cancelName: '{$this->Lang('no')}'
	}).then(function() {
      $(element).val(suggest.full);
	},function() {
      element.focus();
	});
   },
   empty: function(element) {
    var dbg = 1;
//TODO    $.alertable.prompt('{$this->Lang('missing_contact')}').then(function() {
//     element.focus();
//    });
   }
  });
 });
EOS;

/* NB cloaking not compatible with strengthify, cuz the former hides original & works with duplicate object, same id
<script type="text/javascript" src="{$baseurl}/include/jquery-inputCloak.min.js"></script>
.inputCloak({
  type:'see4',
  symbol:'\u25CF'
 })
strengthify unused opts
// TODO titles & messages translation
  titles: [
   'Weakest',
   'Weak',
   'So-so',
   'Good',
   'Perfect'
   ],
  messages: [
   'Getting better.',
   'Looks good.'
  ]
*/
	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/jquery.strengthify.js"></script>
EOS;

	$jsloads[] = <<<EOS
 $('#{$id}privhash').strengthify({
  zxcvbn: '{$baseurl}/include/zxcvbn/zxcvbn.js'
 });
EOS;
} //$pmod

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
