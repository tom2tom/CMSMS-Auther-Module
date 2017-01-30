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
	$one->title = $mod->Lang('current_typed', $mod->Lang('password'));
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth1', $tabindex++, '', 20, 72);
	$elements[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('new_typed', $mod->Lang('password'));
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth2', $tabindex++, '', 20, 72);
	$elements[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('new_typed', $mod->Lang('title_passagain'));
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth3', $tabindex++, '', 20, 72);
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
		$one->input = $this->GetInputText($id, 'captcha', 'auth5', $tabindex++, '', 8, 8);
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
<script type="text/javascript" src="{$baseurl}/include/sjcl.js"></script>
<script type="text/javascript" src="{$baseurl}/include/auth.js"></script>
EOS;

	$jsloads[] = <<<EOS
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
      type = '{$mod->Lang('current_typed',$mod->Lang('password'))}';
      break;
     case 'auth2':
      type = '{$mod->Lang('new_typed',$mod->Lang('password'))}';
     case 'auth3':
      type = '{$mod->Lang('title_passagain')}';
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
  if ($('#auth2').val() !== $('#auth3').val()) {
   doerror($('#auth3'),'{$mod->Lang('password_nomatch')}');
   valid = false;
   setTimeout(function() {
    btn.disabled = false;
   },10);
  }
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
