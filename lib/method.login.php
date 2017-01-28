<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

/* template classes
div#authcontainer
div#authelements
div#authactions
.hidejs
.authtitle
.authtext
.authinput
input#authsend
input#authcancel
#focus

.hidecaptcha ?
.passwd ?
*/

/*
<form action="login.php" method="post">
<p>
<input id="lbusername" class="defaultfocus" type="text" value="" size="15" name="username">
<br>
<input id="lbpassword" type="password" size="15" name="password">
<br>
<input class="loginsubmit" type="submit" value="Submit" name="loginsubmit">
<input class="loginsubmit" type="submit" value="Cancel" name="logincancel">
</p>
</form>
<div class="forgot-pw">
<a href="login.php?forgotpw=1">Forgot your password?</a>
</div>
</div>
*/
/*
	private function LoginData(&$mod, $id, $cdata, $sdata, &$cache, &$hidden,
		&$tplary, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];

		$oneset = new \stdClass();
		$oneset->title = 'GET my title';
        $oneset->input = $this->GetInputText($id, 'titler', 'custid', 32, 40);
		$components[] = $oneset;

		$tplary += $components;
		return;

		if (0) {
			$tplvars['intro'] = $mod->Lang('');
		}
		if (0) {
			$tplvars['after'] = $mod->Lang('');
		}

		if (0) {
			//TODO captcha stuff for nearnonce
		}

		$t = $utils->RandomAlnum(24);
		$hidden[] = $mod->CreateInputHidden($id,'farnonce',$t);
		$hidden[] = $mod->CreateInputHidden($id,'nearnonce','captcha');
		$hidden[] = $mod->CreateInputHidden($id,'hash','');

		$oneset = new \stdClass();
		$oneset->title = $mod->Lang('TODO');
		$t = $mod->CreateInputText($id,'TODO',$val,$len);
		$oneset->input = strtr($t, 'id="'.$id, 'id="');
		if (0) {
//			$onset->extra = ;
		}
		$components[] = $oneset;

//		repeat ...

		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/sjcl.min.js"></script>
EOS;
			//TODO
		$jsfuncs[] = <<<EOS
 sjcl.encrypt("password","data");
EOS;
		 $jsfuncs[] = <<<EOS
// disable form buttons
function onsubmit (ev) {
 $('#authsend,#authcancel').each(function(){
  var btn = this;
  setTimeout(function() {
   btn.disabled = true;
  },10);
 });
// some local validation
 if (0) { //failure
// change object styles per error
// popup alert then
//	focus 1st error
  $('#authsend,#authcancel').each(function(){
   var btn = this;
   setTimeout(function() {
    btn.disabled = false;
   },20);
  });
 } else {
  var far = $('#nearn').val(),
    near = $('#farn').val(),
    key = stringXor(far, near),
    hash = sjcl.func(key, near + far + $('#password').val()); //TODO AS BITS
  $('#jsworks').val(near);
  $('#hash').val(sjcl.codec.base64.fromBits(hash,false,false));
  $('#nearn,#farn,#password').val('');
//  $('#authform1').trigger('submit.deferred'); NO
  $.ajax({
   stuff
  });
 }
 return false;
}
EOS;

/*
iv [-1759984183, 221357109, 480513022, -482356771]
password "Suckitup,crackers"
key []
adata "EXTRA DATA"
aes undefined
plaintext "Hello there, pirates"
rp Object {}
ct undefined
p Object { adata="EXTRA DATA",  iter=1000,  mode="gcm",  more...}
 adata "EXTRA DATA"
 iter 1000
 mode "gcm"
 ts  64
 ks 	128
 iv 	[-1759984183, 221357109, 480513022, -482356771]
 salt 	[1195984120, 1407048864]
}
AFTER ct = sjcl.encrypt(password || key, plaintext, p, rp).replace(/,/g,",\n");

rp Object { iv=[4],  v=1,  iter=1000,  more...}
 iv [-1759984183, 221357109, 480513022, -482356771]
 v 1
 iter 1000
 ks 128
 ts 64
 mode"gcm"
 adata [1163416658, 1092633665, 17593599590400]
 cipher "aes"
 salt [1195984120, 1407048864]
 key	[863892850, 979149439, 285901955, 1290596378]

ct = STRING '{"iv":"lxjFyQ0xpDUcpAv+4z/R3Q==",
 "v":1,
 "iter":1000,
 "ks":128,
 "ts":64,
 "mode":"gcm",
 "adata":"RVhUUkEgREFUQQ==",
 "cipher":"aes",
 "salt":"R0lE+FPd3KA=",
 "ct":"kDDBsShv382GtyIvmYj2wNuKLDXD8h9+/LAhmQ=="}'

$ct = '{
 "iv":"lxjFyQ0xpDUcpAv+4z/R3Q==",
 "v":1,
 "iter":1000,
 "ks":128,
 "ts":64,
 "mode":"gcm",
 "adata":"RVhUUkEgREFUQQ==",
 "cipher":"aes",
 "salt":"R0lE+FPd3KA=",
 "ct":"kDDBsShv382GtyIvmYj2wNuKLDXD8h9+/LAhmQ=="
 }';


		 if (0) { //per $mode

			$jsincs[] = $baseurl.'/include/autho.min.js';
			//TODO local data validation js if relevant
			//TODO $jsincs[] = $baseurl.'/include/zxcvbn/zxcvbn.js if relevant

			$jsloads[] = <<<EOS
$('#authsend').click.function() {
 var n1 = $('#{$id}farnonce').val();
 var n2 = randomAlnum(24);
 $('#{$id}hash').val(sha1(n1 + n2 + $('#passwd').val()));
 $('#{$id}nearnonce').val(n2);
 $('#passwd').val('');
 var btn = this;
 setTimeout(function() {
  btn.disabled = true;
 },10);
}
EOS;
			if ($withcancel) {
				$jsloads[] = <<<EOS
$('#authcancel').click.function() {
 $('#{$id}farnonce').val('');
 $('#{$id}nearnonce').val('');
 $('#passwd').val('');
}
EOS;
			}
		}

		if (0) {
//			TODO strengthify styles needed - HOW?
			$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/jquery.strengthify.js"></script>
EOS;
			$jsloads[] = <<<EOS
 $('#authelements .passwd').strengthify({

 });
EOS;
		}
		$tplary += $components;
	}
 */

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

//append as appropriate to arrays: $cache, $hidden, $elements, $tplvars, $jsincs, $jsfuncs, $jsloads
switch ($cdata['security_level']) {
 case self::NOBOT:
	//setup for reCaptcha
	break;

 case self::NONCED:
	//no break here
	//XTRA UI (POSITIONED LAST)
	//XTRA JS
 case self::LOSEC:
 	$one = new \stdClass();
	if ($cdata['email_required']) {
		$one->title = $mod->Lang('title_email');
		$one->input = $this->GetInputText($id, 'login', 'auth1', '', 32, 96);
	} else {
		$one->title = $mod->Lang('title_login');
		$one->input = $this->GetInputText($id, 'login', 'auth1', '', 20, 32);
	}
	$elements[] = $one;

	$one = new \stdClass();
	$one->title = $mod->Lang('password');
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth2', '', 20, 72);
	if ($cdata['forget_rescue']) {
		$one->extra = '<span style="vertical-align:30%;">'.$mod->Lang('lostpass').'</span>&nbsp;&nbsp;'.$this->GetInputCheck($id, 'recover', 'auth3', FALSE);
	}
	$elements[] = $one;

//<script type="text/javascript" src="{$baseurl}/include/jquery.alertable.min.js"></script> N/A unless its styling can be provided
	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/mailcheck.min.js"></script>
<script type="text/javascript" src="{$baseurl}/include/levenshtein.min.js"></script>
<script type="text/javascript" src="{$baseurl}/include/sjcl.js"></script>
<script type="text/javascript" src="{$baseurl}/include/auth.js"></script>
EOS;

	$pref = $mod->GetPreference('email_topdomains');
	$topdomains = ConvertDomains($pref);
	if ($topdomains) {
		$topdomains = <<<EOS

   topLevelDomains: [$topdomains],
EOS;
	}
	$pref = $mod->GetPreference('email_domains');
	$domains = ConvertDomains($pref);
	if ($domains) {
		$domains = <<<EOS

   domains: [$domains],
EOS;
	}
	$pref = $mod->GetPreference('email_subdomains');
	$l2domains = ConvertDomains($pref);
	if ($l2domains) {
		$l2domains = <<<EOS

   secondLevelDomains: [$l2domains],
EOS;
	}

	$jsloads[] = <<<EOS
 $('#auth1').blur(function() {
  $(this).mailcheck({{$domains}{$l2domains}{$topdomains}
   distanceFunction: function(string1,string2) {
    var lv = Levenshtein;
    return lv.get(string1,string2);
   },
   suggested: function(element,suggest) {
    var msg = '{$mod->Lang('meaning_type','%s')}'.replace('%s',suggest.full);
    if (confirm(msg)) {
     $(element).val(suggest.full);
    } else {
     var dbg = 1;
     element.focus();
    }
   },
   empty: function(element) {
    var dbg = 1;
    alert('{$mod->Lang('missing_login')}');
    element.focus();
   }
  });
 });
 $('#authsend').click(function() {
//  var btn = this;
//  setTimeout(function() {
//   btn.disabled = true;
//  },10);
  //TODO key = something known upstream
  //iv & salt generated and/or known
  //ks = keysize, ts = authetication-tag size
  //TODO upstream usable mode
//    iv = [-1759984183, 221357109, 480513022, -482356771],
//    salt = [1195984120, 1407048864],
/* iter: 1024,
   mode: 'gcm',
   ks: 128,
   ts: 64,
   iv: iv,
   salt: salt

  var key = randomAlnum(12),
    rp = {},
  json = sjcl.encrypt(key,$('#auth2').val(),{
   mode: 'gcm',
   iter:1024
  },rp);
//TODO get salt etc from rp
  $('#auth2').val(json);
*/
  var passwd = 'Suck it up, crackers';
  var salt = randomBytes(16);
  var dbg = sjcl.pbkdf2(password, salt, 1024);
  //TODO ajax stuff
  return false;
 });
EOS;
	if ($withcancel) {
		$jsloads[] = <<<EOS
 $('#authcancel').click(function() {
  $('#auth1,#auth2').val('');
 });
EOS;
	}
	break;

 case self::CHALLENGED:
	break;

 case self::HISEC:
	break;
} //switch level
