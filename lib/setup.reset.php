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

switch ($cdata['security_level']) {
 case self::NOBOT:
	$one = new \stdClass();
	$one->title = $mod->Lang('noauth');
	$elements[] = $one;
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
 case self::NONCED:
 case self::CHALLENGED:
	$one = new \stdClass();
	if ($cdata['email_required']) {
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
	$one->title = $mod->Lang('current_typed', $mod->Lang('password'));
	$one->input = $this->GetInputPasswd($id, 'passwd', 'passwd', $tabindex++, '', 20, 72);
	$elements[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('new_typed', $mod->Lang('password'));
	$one->input = $this->GetInputPasswd($id, 'passwd2', 'passwd2', $tabindex++, '', 20, 72);
	$elements[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('new_typed', $mod->Lang('title_passagain'));
	$one->input = $this->GetInputPasswd($id, 'passwd3', 'passwd3', $tabindex++, '', 20, 72);
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
	 case self::NONCED:
		$far = $this->UniqueToken(32);
		$cache['far'] = $far;
		$far2 = strtr($far, ['"'=>'\"']);
		$hidden[] = $mod->CreateInputHidden($id,'nearn','');
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
  passwd: $('#passwd').val(),
  passwd2: $('#passwd2').val()
 }),
  far = "$far2",
  iv = GibberAES.a2s(GibberAES.randArr(16));
 var parms = {
  {$id}jsworks: 'TRUE',
  {$id}sent: GibberAES.encString(far+sent,far,iv)
 };
 $('#{$id}nearn').val(GibberAES.Base64.encode(iv));
 $('#authcontainer input:hidden').add(\$inputs).each(function() {
  var \$el = $(this),
   v = \$el.val(),
   t, n;
  if (v) {
   t = \$el.attr('type');
   if (t == 'password') {
    return;
   } else if (t == 'checkbox' && !\$el.is(':checked')) {
    v = '0';
   }
   n = \$el.attr('name');
   parms[n] = v;
  }
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
      type = '{$mod->Lang('current_typed',$mod->Lang('password'))}';
      break;
     case 'passwd2':
      type = '{$mod->Lang('new_typed',$mod->Lang('password'))}';
      break;
     case 'passwd3':
      type = '{$mod->Lang('title_passagain')}';
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
       doerror(\$el,'{$mod->Lang('email_invalid')}');
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
    success: function(data, status, jqXHR) {
     if (status=='success') {
   //stuff
     var details = JSON.parse(jqXHR.responseText);
     ajaxresponse (details, false);
     } else {
   //stuff e.g. show jqXHR.responseText, jqXHR.statusText
     }
     $(btn).prop('disabled', false);
    },
    error: function(jqXHR, status, errmsg) {
     details = JSON.parse(jqXHR.responseText);
     ajaxresponse (details, errmsg);
     $(btn).prop('disabled', false);
    }
   });
  } else {
    setTimeout(function() {
     $(btn).prop('disabled', false);
    },10);
  }
  return false;
 });
EOS;
	break;

 case self::HISEC:
	break;
} //switch level
