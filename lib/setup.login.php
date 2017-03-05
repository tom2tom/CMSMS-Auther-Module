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
from $cfuncs->decrypt_preference('recaptcha_secret'); //6LfgfxMUAAAAAEmGmfYe5gL_kBTq2bs82dGVcEVQ
response (required)	The value of 'g-recaptcha-response' $_POST['g-recaptcha-response']
remoteip	The end-user's ip address $_SERVER['REMOTE_ADDR']

see https://developers.google.com/recaptcha/docs/display
 requires handler function to be defined before the include
 render parameters @ https://developers.google.com/recaptcha/docs/display#render_param
*/
switch ($cdata['security_level']) {
 case self::NOBOT:
	$pubkey = $mod->GetPreference('recaptcha_key');
	if ($pubkey) {
		$one = new \stdClass();
		$one->input = '<div id="g-recaptcha"></div>';
		$elements[] = $one;
		//fallback if no js
		$one = new \stdClass();
		$one->title = $mod->Lang('title_captcha');
		$one->subtitle = $mod->Lang('title_captcha2');
		list($t,$img) = $this->CaptchaImage($mod);
		$one->img = $img;
		$one->input = $this->GetInputText($id, 'captcha', 'captcha', $tabindex++, '', 8, 8);
		$tplvars['captcha'] = $one;
	} else {
		//TODO present captcha in conventional layout
		$one = new \stdClass();
		$one->title = $mod->Lang('title_captcha2');
		$one->input = $this->GetInputText($id, 'captcha', 'captcha', $tabindex++, '', 8, 8);
		list($t,$img) = $this->CaptchaImage($mod);
		$one->xtra = $img;
		$elements[] = $one;
	}
	//TODO record $t code for later use
	$cache['captcha'] = $t;
	//TODO js for captcha processing ETC
	//javascript:alert(grecaptcha.getResponse(widgetId1));
	//<script type="text/javascript" src="{$baseurl}/include/auth.js"></script>
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
	//TODO validate reCaptcha via js API
	//TODO filter parms as appropriate
	$jsfuncs[] = <<<EOS
function transfers(\$inputs) {
 var parms = {};
 $('#authcontainer input:hidden').add(\$inputs).each(function() {
  var \$el = $(this),
   n = \$el.attr('name');
  parms[n] = \$el.val();
 });
 return parms;
}
EOS;
	break;

 case self::LOSEC:
 case self::MIDSEC:
 case self::CHALLENGED:
	$one = new \stdClass();
	if ($cdata['email_login']) {
		$one->title = $mod->Lang('title_email');
		$one->input = $this->GetInputText($id, 'login', 'login', $tabindex++, '', 32, 96);
        $logtype = 0;
	} else {
		$one->title = $mod->Lang('title_login');
		$one->input = $this->GetInputText($id, 'login', 'login', $tabindex++, '', 20, 32);
        $logtype = 1;
	}
	$elements[] = $one;

	$one = new \stdClass();
	$one->title = $mod->Lang('password');
	$one->input = $this->GetInputPasswd($id, 'passwd', 'passwd', $tabindex++, '', 20, 72);
	if ($cdata['password_rescue']) {
		$one->extra = '<label for="recover">'.$mod->Lang('lostpass').'</label>'.
		$this->GetInputCheck($id, 'recover', 'recover', $tabindex++, FALSE);
	} else {
		$one->extra = $mod->Lang('lostpass_renew');
	}
	$elements[] = $one;

	switch ($cdata['security_level']) {
	 case self::LOSEC:
		//TODO filter parms as appropriate
		$jsfuncs[] = <<<EOS
function transfers(\$inputs) {
 var parms = {};
 $('#authcontainer input:hidden').add(\$inputs).each(function() {
  var \$el = $(this),
   n = \$el.attr('name');
  parms[n] = \$el.val();
 });
 return parms;
}
EOS;
		break;
	 case self::MIDSEC:
		$far = $this->UniqueToken(32);
		$cache['far'] = $far;
		$far = strtr($far, ['\\'=>'\\\\', '"'=>'\"']);
		$hidden[] = $mod->CreateInputHidden($id, 'nearn', '');
		$one = new \stdClass();
		$one->title = $mod->Lang('title_captcha');
		$one->subtitle = $mod->Lang('title_captcha2');
		list($t,$img) = $this->CaptchaImage($mod);
		$cache['captcha'] = $t;
		$one->img = $img;
		$one->input = $this->GetInputText($id, 'captcha', 'captcha', $tabindex++, '', 8, 8);
		$tplvars['captcha'] = $one;

		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/gibberish-aes.js"></script>
EOS;
		//function returns js object
		$jsfuncs[] = <<<EOS
function transfers(\$inputs) {
 var sent = JSON.stringify({
  passwd: $('#passwd').val()
 }),
  far = "$far",
  iv = GibberAES.a2s(GibberAES.randArr(16));
 var parms = {
  {$id}jsworks: 'TRUE',
  {$id}sent: GibberAES.encString(far+sent,far,iv)
 };
 $('#{$id}nearn').val(GibberAES.Base64.encode(iv));
 $('#authcontainer input:hidden').add(\$inputs).each(function() {
  var \$el = $(this),
   t = \$el.attr('type'),
   n, v;
  if (t == 'password') {
   return;
  } else if (t == 'checkbox' && !\$el.is(':checked')) {
   v = '0';
  } else {
   v = \$el.val();
  }
  n = \$el.attr('name');
  parms[n] = v;
 });
 return parms;
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
 $('#login').blur(function() {
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
 $('#authsubmit').click(function() {
  var btn = this;
  setTimeout(function() {
   btn.disabled = true;
  },10);
  var valid = true,
   \$ins = $('#authelements input');
  \$ins.each(function() {
   var \$el = $(this),
     id = \$el.attr('id'),
    val = \$el.val();
   if (val == '') {
    var type;
    switch (id) {
     case 'login':
      type = ({$logtype}) ? '{$mod->Lang('title_login')}':'{$mod->Lang('title_email')}';
      break;
     case 'passwd':
      var \$cb = $('#recover');
      if (\$cb.length > 0 && \$cb.val() > 0) { return; }
      type = '{$mod->Lang('password')}';
      break;
     case 'captcha':
      return;
    }
    var msg = '{$mod->Lang('missing_type','%s')}'.replace('%s',type);
    doerror(\$el,msg);
    valid = false;
    return false;
   } else {
    if (id == 'login') {
     if (!{$logtype}) {
      if (val.search(/^.+@.+\..+$/) == -1) {
       doerror(\$el,'{$mod->Lang('invalid_type',$mod->Lang('title_email'))}');
       valid = false;
       return false;
      }
     }
    }
   }
  });
  if (valid) {
   var parms = transfers(\$ins);
   $.ajax({
    type: 'POST',
    method: 'POST',
    url: '$url',
    data: parms,
    dataType: 'json',
    global: false,
    success: function(data,status,jqXHR) {
     switch (jqXHR.status) {
      case 202:
       var \$el = $('#authform');
       \$el.find(':input:not([type=hidden])').removeAttr('name');
	   \$el.prepend('<input type="hidden" name="{$id}success" value="1" />');
       \$el.trigger('submit');
       break;
      case 200:
       ajaxresponse(jqXHR.responseJSON,somemsg);
       break;
      default:
       break;
     }
     $(btn).prop('disabled',false);
    },
    error: function(jqXHR,status,errmsg) {
     details = JSON.parse(jqXHR.responseText);
     ajaxresponse (details, errmsg);
     $(btn).prop('disabled',false);
    }
   });
  } else {
    setTimeout(function() {
     $(btn).prop('disabled',false);
    },10);
  }
  return false;
 });
EOS;
	break;

 case self::HISEC:
	break;
} //switch level
