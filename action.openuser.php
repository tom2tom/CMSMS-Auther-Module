<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$uid = (int)$params['item_id']; //-1 for new user
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
	$this->Redirect($id, 'users', '', ['item_id'=>$params['context']]); //TODO parms
} elseif (isset($params['submit'])) {
//TODO verify & save stuff
//TODO encrypt address,passhash
	$this->Redirect($id, 'users', '', ['item_id'=>$params['context']]);
}

$cfuncs = new Auther\Crypter();
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
	'context' => $params['context'], //TODO if not numeric
	'passhash' => '',
	'address' => '',
	'active' => 1
	];
}

$cdata = $db->GetRow('SELECT name,password_min_length,password_min_score,address_required,email_required FROM '.$pre.'module_auth_contexts WHERE id=?', [$data['context']]);

$utils = new Auther\Utils();

$tplvars = ['mod' => $pmod];
$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = [
	'context'=>$data['context'],
	'user_id'=>$data['id'],
	'edit'=>!empty($params['edit'])
]; //TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'openuser',$returnid,'POST',
	'','','',$hidden);
$tplvars['endform'] = $this->CreateFormEnd();
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
$one = new stdClass();
$kn = 'identifier';
$val = $data['publicid'];
$one->title = $this->Lang('title_'.$kn);
if ($pmod) {
	$one->input = $this->CreateInputText($id, $kn, $val, 48);
} else {
	$one->input = $val;
}
$one->must = 1;
$kn = 'help_'.$kn;
if (langhasval($this, $kn)) {
	$one->help = $this->Lang($kn);
}
$options[] = $one;

$one = new stdClass();
$kn = 'contact';
$val = $cfuncs->decrypt_value ($this, $data['address']);
$one->title = $this->Lang('title_'.$kn);
if ($pmod) {
	$one->input = $this->CreateInputText($id, $kn, $val, 48, 96);
} else {
	$one->input = $val;
}
$one->must = ($cdata['address_required'] > 0 || $cdata['email_required'] > 0);
if ($cdata['email_required']) {
	$kn = 'help_'.$kn;
	$one->help = $this->Lang($kn);
	if ($pmod) {
		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/mailcheck.js"></script>
<script type="text/javascript" src="{$baseurl}/include/levenshtein.min.js"></script>
<script type="text/javascript" src="{$baseurl}/include/jquery.alertable.min.js"></script>
EOS;

	function ConvertDomains($pref)
	{
		if (!$pref)
			return FALSE; //'""';
		$parts = explode(',',$pref);
		if (isset($parts[1])) { //>1 array-member
			$parts = array_unique($parts);
			ksort($parts);
		}
		foreach ($parts as &$one) {
			$one = '\''.trim($one).'\'';
		}
		unset($one);
		return implode(',',$parts);
	}

		$pref = $this->GetPreference('email_topdomains');
		$topdomains = ConvertDomains($pref);
		if ($topdomains) {
			$topdomains = <<<EOS

   topLevelDomains: [$topdomains],
EOS;
		} else {
			$topdomains = '';
		}
		$pref = $this->GetPreference('email_domains');
		$domains = ConvertDomains($pref);
		if ($domains) {
			$domains = <<<EOS

   domains: [$domains],
EOS;
		} else {
			$domains = '';
		}
		$pref = $this->GetPreference('email_subdomains');
		$l2domains = ConvertDomains($pref);
		if ($l2domains) {
			$l2domains = <<<EOS

   secondLevelDomains: [$l2domains],
EOS;
		} else {
			$l2domains = '';
		}

		$jsincs[] = <<<EOS
EOS;

		$jsloads[] = <<<EOS
 $('#{$id}contact').blur(function() {
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
    $.alertable.prompt('{$this->Lang('missing_contact')}').then(function() {
     element.focus();
    });
   }
  });
 });
EOS;
	} //$pmod
} //require email

$options[] = $one;

if ($pmod) {
	$one = new stdClass();
	$one->title = $this->Lang('title_password_new');
	$one->input = $this->CreateInputText($id, 'password_new', '', 48, 72);
	$one->must = 0;
	$short = (int)$cdata['password_min_length'];
	$score = (int)$cdata['password_min_score'];
	$one->help = $this->Lang('help_password_new', $short, $score);
	$options[] = $one;

/* NB cloaking not compatible with strengthify
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
 $('#{$id}password_new').strengthify({
  zxcvbn: '{$baseurl}/include/zxcvbn/zxcvbn.js'
 });
EOS;
} //$pmod

$one = new stdClass();
$kn = 'active';
$val = $data[$kn];
$one->title = $this->Lang('title_'.$kn);
if ($pmod) {
	$one->input = $this->CreateInputCheckbox($id, $kn, 1, $val);
} else {
	$one->input = ($val) ? $yes : $no;
}
$one->must = 0;
$kn = 'help_'.$kn;
if (langhasval($this, $kn)) {
	$one->help = $this->Lang($kn);
}
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
