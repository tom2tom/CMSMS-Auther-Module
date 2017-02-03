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
	break;

 case self::LOSEC:
 case self::NONCED:
 case self::CHALLENGED:
	$one = new \stdClass();
	if ($cdata['email_required']) {
		$one->title = $mod->Lang('current_typed', $mod->Lang('title_email'));
		$one->input = $this->GetInputText($id, 'login', 'login', $tabindex++, '', 32, 96);
        $logtype = 0;
	} else {
		$one->title = $mod->Lang('current_typed', $mod->Lang('title_login'));
		$one->input = $this->GetInputText($id, 'login', 'login', $tabindex++, '', 20, 32);
        $logtype = 1;
	}
	$elements[] = $one;

	$one = new \stdClass();
	$one->title = $mod->Lang('current_typed', $mod->Lang('password'));
	$one->input = $this->GetInputPasswd($id, 'passwd', 'passwd', $tabindex++, '', 20, 72);
	if ($cdata['forget_rescue']) {
		$one->extra = '<span style="vertical-align:30%;">'.$mod->Lang('lostpass').'</span>&nbsp;&nbsp;'.$this->GetInputCheck($id, 'recover', 'recover', $tabindex++, FALSE);
	}
	$elements[] = $one;

	$same = $mod->Lang('blank_same');

	$one = new \stdClass();
	if ($logtype == 0) {
		$one->title = $mod->Lang('new_typed', $mod->Lang('title_email'));
		$one->input = $this->GetInputText($id, 'login2', 'login2', $tabindex++, '', 32, 96);
		$one->extra = $mod->Lang('help_contact').'<br />'.$same;
	} else {
		$one->title = $mod->Lang('new_typed', $mod->Lang('title_login'));
		$one->input = $this->GetInputText($id, 'login2', 'login2', $tabindex++, '', 20, 32);
		$one->extra = $mod->Lang('help_login').'<br />'.$same;
	}
	$elements[] = $one;

 	$one = new \stdClass();
	if($cdata['name_required']) {
		$one->title = $mod->Lang('new_typed', $mod->Lang('name'));
		$optname = 0;
	} else {
		$one->title = $mod->Lang('new_typed', $mod->Lang('name_opt'));
		$optname = 1;
	}
	$one->input = $this->GetInputText($id, 'name', 'name', $tabindex++, '', 20, 32);
	$one->extra = $same;
	$elements[] = $one;

	if ($logtype == 1) {
	 	$one = new \stdClass();
		if ($cdata['address_required']) {
			$one->title = $mod->Lang('new_typed', $mod->Lang('title_contact'));
			$optcontact = 0;
		} else {
			$one->title = $mod->Lang('new_typed', $mod->Lang('contact_opt'));
			$optcontact = 1;
		}
		$one->input = $this->GetInputText($id, 'contact', 'contact', $tabindex++, '', 32, 96);
		$one->extra = $mod->Lang('help_contact2').'<br />'.$same;
		$elements[] = $one;
	} else {
		$optcontact = 1;
	}

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
		$one->input = $this->GetInputText($id, 'captcha', 'captcha', $tabindex++, '', 8, 8);
		$tplvars['captcha'] = $one;
	//TODO js for captcha processing ETC
		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/sjcl.js"></script>
<script type="text/javascript" src="{$baseurl}/include/auth.js"></script>
EOS;
		//TODO filter parms as appropriate
		$jsfuncs[] = <<<EOS
function transfers(\$inputs) {
 var far = $('#farn').val(),
    near = randomBytes(16),
    key = stringXor(far,near),
    hash = encryptVal(near + far + $('#passwd').val(),key);
 $('#nearn').val(base64encode(near));
 $('#hash').val(base64encode(hash));
 $('#farn,#passwd').val('');
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
 $('#login,#login2,#contact').blur(function() {
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
    }
    var msg = '{$mod->Lang('missing_type','%s')}'.replace('%s',type);
    doerror(\$el,msg);
    valid = false;
    return false;
   } else {
    if (id == 'login' || id == 'login2') {
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
    dataType: 'text',
    global: false,
    success: function(data, status, jqXHR) {
     if (status=='success') {
   //stuff
     } else {
   //stuff e.g. show jqXHR.responseText, jqXHR.statusText
     }
    },
    error: function(jqXHR, status, errmsg) {
     var details = JSON.parse(jqXHR.responseText);
	//TODO process details
     btn.disabled = false;
    }
   });
  } else {
    setTimeout(function() {
     btn.disabled = false;
    },10);
  }
  return false;
 });
EOS;
	break;

 case self::HISEC:
	break;
} //switch level
