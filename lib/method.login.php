<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

if (0) {
	$tplvars['intro'] = $mod->Lang('TODO');
}
if (0) {
	$tplvars['after'] = $mod->Lang('TODO');
}

/*
parameters @ https://developers.google.com/recaptcha/docs/display#render_param
 When the form is submitted, part of the payload will be a string with the name
"g-recaptcha-response". In order to check whether Google has verified that user,
send a POST request with these parameters:
URL: https://www.google.com/recaptcha/api/siteverify
secret (required)	the secret key
from $cfuncs->decrypt_preference($mod,'recaptcha_secret'); //6LfgfxMUAAAAAEmGmfYe5gL_kBTq2bs82dGVcEVQ
response (required)	The value of 'g-recaptcha-response' $_POST['g-recaptcha-response']
remoteip	The end-user's ip address $_SERVER['REMOTE_ADDR']

see https://developers.google.com/recaptcha/docs/display
 requires handler function to be defined before the include
 render parameters @ https://developers.google.com/recaptcha/docs/display#render_param
*/
switch ($cdata['security_level']) {
 case self::NOBOT:
//	$pubkey = $mod->GetPreference('recaptcha_key');
	$pubkey = '6LfgfxMUAAAAALXMQlujx_YF3p3fkv6pjmWwVdaI';
	$one = new \stdClass();
	$one->input = '<div id="g-recaptcha"></div>';
	$elements[] = $one;
	//fallback if no js
 	$one = new \stdClass();
	$one->title = $mod->Lang('title_captcha');
	$one->subtitle = $mod->Lang('title_captcha2');
	list($t,$img) = $this->CaptchaImage($mod);
	//TODO record $t code for later use
	$one->img = $img;
	$one->input = $this->GetInputText($id, 'captcha', 'auth5', $tabindex++, '', 8, 8);
	$tplvars['captcha'] = $one;
	//TODO backend for captcha processing
	//TODO captcha encoding per $config['locale'] if that exists or else Lang setting?
	// add to URL &hl=whatever with 'en' for 'en_US' etc
	//this hack forced by mandatory ordering of recaptcha js
	$jsincs[] = <<<EOS
<script type="text/javascript">
//<![CDATA[
function onloadCallback() {
 var widgetID = grecaptcha.render('g-recaptcha',{
  'sitekey': '$pubkey'
 });
}
//]]>
</script>
<script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit" async defer></script>
EOS;
	break;

 case self::LOSEC:
 case self::NONCED:
 case self::CHALLENGED:
	$one = new \stdClass();
	if ($cdata['email_required']) {
		$one->title = $mod->Lang('title_email');
		$one->input = $this->GetInputText($id, 'login', 'auth1', $tabindex++, '', 32, 96);
        $logtype = 0;
	} else {
		$one->title = $mod->Lang('title_login');
		$one->input = $this->GetInputText($id, 'login', 'auth1', $tabindex++, '', 20, 32);
        $logtype = 1;
	}
	$elements[] = $one;

	$one = new \stdClass();
	$one->title = $mod->Lang('password');
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth2', $tabindex++, '', 20, 72);
	if ($cdata['forget_rescue']) {
		$one->extra = '<span style="vertical-align:30%;">'.$mod->Lang('lostpass').'</span>&nbsp;&nbsp;'.$this->GetInputCheck($id, 'recover', 'auth3', $tabindex++, FALSE);
	}
	$elements[] = $one;

	switch ($cdata['security_level']) {
	 case self::NONCED:
		$t = $utils->RandomAlnum(24);
	//TODO record $t for later use in session
		$hidden[] = $mod->CreateInputHidden($id,'farn',$t);
		$hidden[] = $mod->CreateInputHidden($id,'nearn','');
		$one = new \stdClass();
		$one->title = $mod->Lang('title_captcha');
		$one->subtitle = $mod->Lang('title_captcha2');
		list($t,$img) = $this->CaptchaImage($mod);
	//TODO record $t code for later use
		$one->img = $img;
		$one->input = $this->GetInputText($id, 'captcha', 'auth4', $tabindex++, '', 8, 8);
		$tplvars['captcha'] = $one;
	//TODO js for captcha processing ETC
		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/sjcl.js"></script>
<script type="text/javascript" src="{$baseurl}/include/auth.js"></script>
EOS;
		$jsfuncs[] = <<<EOS
function whatever() {
 var far = $('#farn').val(),
    near = randomBytes(24),
    key = stringXor(far, near),
    hash = encryptVal(key, near + far + $('#auth2').val());
 $('#nearn').val(base64encode(near));
 $('#hash').val(base64encode(hash));
 $('#farn,#auth2').val('');
/* $.ajax({
  //stuff
 });
*/
}
EOS;
		break;
	 case self::CHALLENGED:
		//TODO
		break;
	}

//<script type="text/javascript" src="{$baseurl}/include/jquery.alertable.min.js"></script> N/A unless its styling can be provided
	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/mailcheck.min.js"></script>
<script type="text/javascript" src="{$baseurl}/include/levenshtein.min.js"></script>
<script type="text/javascript" src="{$baseurl}/include/sjcl.js"></script>
<script type="text/javascript" src="{$baseurl}/include/auth.js"></script>
EOS;

	$pref = $mod->GetPreference('email_topdomains');
	$topdomains = $this->ConvertDomains($pref);
	if ($topdomains) {
		$topdomains = <<<EOS

   topLevelDomains: [$topdomains],
EOS;
	}
	$pref = $mod->GetPreference('email_domains');
	$domains = $this->ConvertDomains($pref);
	if ($domains) {
		$domains = <<<EOS

   domains: [$domains],
EOS;
	}
	$pref = $mod->GetPreference('email_subdomains');
	$l2domains = $this->ConvertDomains($pref);
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
     element.focus();
    }
   }
  });
 });
 $('#authsend').click(function() {
  var btn = this,
   valid = true;
  setTimeout(function() {
   btn.disabled = true;
  },10);
  $('#authelements input').each(function() {
   var \$el = $(this);
   if (\$el.val() == '') {
    var id = \$el.attr('id'),
     type;
    switch (id) {
     case 'auth1':
      type = ({$logtype}) ? '{$mod->Lang('title_login')}':'{$mod->Lang('title_email')}';
      break;
     case 'auth2':
      var \$cb = $('#auth3');
      if (\$cb.length > 0 && \$cb.val() > 0) { return; }
      type = '{$mod->Lang('password')}';
      break;
    }
    var msg = '{$mod->Lang('missing_type','%s')}'.replace('%s',type);
    doerror(\$el,msg);
    valid = false;
    setTimeout(function() {
     btn.disabled = false;
    },10);
    return false;
   }
  });
  if (valid) {
//TODO encryption
//TODO ajax stuff
  }
  return false;
 });
EOS;
	break;

 case self::HISEC:
	break;
} //switch level
