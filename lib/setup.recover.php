<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

switch ($lvl) {
 case self::NOBOT:
	$one = new \stdClass();
	$one->title = $mod->Lang('noauth');
	$elements1[] = $one;
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
	$hidden[] = $mod->CreateInputHidden($id, 'phase', 'who');

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
	$elements1[] = $one;

	$one = new \stdClass();
	$one->title = $mod->Lang('token');
//	$one->extra = $mod->Lang('help_password_token');
	$one->input = $this->GetInputPasswd($id, 'passwd', 'passwd', $tabindex++, '', 12, 20);
	$one->extra = $mod->Lang('help_password_recover');
	$elements2[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('new_typed', $mod->Lang('password'));
	$one->input = $this->GetInputPasswd($id, 'passwd2', 'passwd2', $tabindex++, '', 20, 72);
	$n = (int)$cdata['password_min_length'];
	$one->extra = $mod->Lang('help_password', $n);
	$elements2[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('new_typed', $mod->Lang('title_passagain'));
	$one->input = $this->GetInputPasswd($id, 'passwd3', 'passwd3', $tabindex++, '', 20, 72);
	$elements2[] = $one;

	switch ($lvl) {
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
<script type="text/javascript" src="{$baseurl}/lib/js/gibberish-aes.min.js"></script>
EOS;
		//function returns js object
		$jsfuncs[] = <<<EOS
function transfers(\$inputs) {
 var far = "$far",
  iv = GibberAES.a2s(GibberAES.randArr(16)),
  parms = {
   {$id}jsworks: 'TRUE',
   {$id}sent: ''
  },
  passes = {},
  v;
 $('#{$id}nearn').val(GibberAES.Base64.encode(iv));
 $('#authcontainer input:hidden').add(\$inputs).each(function() {
  var \$el = $(this),
   t = \$el.attr('type'),
   n;
  if (t == 'password') {
   v = \$el.val();
   if (v != '') {
    n = this.id;
    passes[n] = v;
    return;
   }
  } else if (t == 'checkbox' && !\$el.is(':checked')) {
   v = '0';
  } else {
   v = \$el.val();
  }
  n = this.name
  parms[n] = v;
 });
 v = JSON.stringify(passes);
 parms.{$id}sent = GibberAES.encString(far+v,far,iv);
 return parms;
}
function reports() {
 var parms = {};
 $('#authelements input[type!="password"]').each(function() {
  var n = this.id;
  parms[n] = $(this).val();
 });
 return parms;
}
EOS;
		break;
	 case self::CHALLENGED:
		//TODO
		break;
	}

//<script type="text/javascript" src="{$baseurl}/lib/js/jquery.alertable.min.js"></script> N/A unless its styling can be provided
	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/lib/js/mailcheck.min.js"></script>
<script type="text/javascript" src="{$baseurl}/lib/js/levenshtein.min.js"></script>
EOS;
	$jsfuncs[] = <<<EOS
var phase2 = false;
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
      if (!phase2) {
       return;
      }
      type = '{$mod->Lang('title_password_token')}';
      break;
     case 'passwd2':
      if (!phase2) {
       return;
      }
      type = '{$mod->Lang('new_typed',$mod->Lang('password'))}';
      break;
     case 'passwd3':
      if (!phase2) {
       return;
      }
      type = '{$mod->Lang('title_passagain')}';
      break;
     default:
      return;
    }
    var msg = '{$mod->Lang('missing_type','%s')}'.replace('%s',type);
    doerror(\$el,msg);
    valid = false;
    return false;
   } else {
    switch (id) {
     case 'login':
      if ($logtype == 0) {
       if (val.search(/^.+@.+\..+$/) == -1) {
        doerror(\$el,'{$mod->Lang('invalid_type',$mod->Lang('title_email'))}');
        valid = false;
        return false;
       }
      }
      break;
     case 'passwd2':
      var \$el2 = \$ins.filter('#passwd3');
      if (\$el2.val() !== val) {
       doerror(\$el2,'{$mod->Lang('newpassword_nomatch')}');
       valid = false;
       return false;
      }
      break;
     case 'passwd3':
      var val2 = \$ins.filter('#passwd2').val();
      if (val2 !== val) {
       doerror(\$el,'{$mod->Lang('newpassword_nomatch')}');
       valid = false;
       return false;
      }
     default:
      break;
    }
   }
  });
  if (valid) {
// document.body.style.cursor = 'wait';
   var details,
    parms = transfers(\$ins);
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
      case 206:
       $('#authelements #phase1,#phase2').css('display','none');
       var \$el = $('#authform');
       \$el.find(':input:not([type=hidden])').removeAttr('name');
       details = JSON.parse(jqXHR.responseText);
       if (jqXHR.status == 202) {
        ajaxresponse(details,'{$mod->Lang('title_completed')}',false);
        \$el.prepend('<input type="hidden" name="{$id}success" value="'+details.success+'" />');
        parms = reports();
        parms.password = 'VALIDATED';
        parms.passwordnew = 'RECORDED';
        parms.task = 'recover';
        parms.success = 1;
       } else {
        ajaxresponse(details,'{$mod->Lang('reset_now')}',true);
        \$el.prepend('<input type="hidden" name="{$id}success" value="0" />');
        parms = {};
        parms.task = 'reset';
        parms.repeat = 1;
       }
       var send = GibberAES.Base64.encode(JSON.stringify(parms));
       \$el.prepend('<input type="hidden" name="{$id}authdata" value="'+send+'" />');
       setTimeout(function() {
        \$el.trigger('submit');
       },1000);
       break;
      case 204:
       clearresponse();
       $('#authelements #phase1,#phase2').css('display','block');
       break;
      case 200:
       clearresponse();
//     document.body.style.cursor = 'auto';
       $(btn).prop('disabled',false);
       $('#authelements #phase2').css('display','block');
       \$el = $('#authelements #passwd');
       \$el.val('');
       \$el[0].focus();
       $('#{$id}phase').val('what');
       phase2 = true;
       break;
      default:
       break;
     }
    },
    error: function(jqXHR,status,errmsg) {
     details = JSON.parse(jqXHR.responseText);
     ajaxresponse(details,errmsg,true);
     $(btn).prop('disabled',false);
//   document.body.style.cursor = 'auto';
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
