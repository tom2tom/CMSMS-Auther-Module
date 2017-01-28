<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

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

switch ($cdata['security_level']) {
 case self::NOBOT:
 	$one = new \stdClass();
	$one->title = $mod->Lang('');
//MESSAGE - 'Nothing is required for this'
	$elements[] = $one;
	break;

 case self::NONCED:
	//no break here
	//XTRA UI (POSITIONED LAST)
	//XTRA JS
 case self::LOSEC:
	$one = new \stdClass();
	$one->title = $mod->Lang('password'); //TODO OLD
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth1', '', 20, 72);
	$elements[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('password'); //TODO NEW
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth2', '', 20, 72);
	$elements[] = $one;
	$one = new \stdClass();
	$one->title = $mod->Lang('title_passagain'); //TODO NEW
	$one->input = $this->GetInputPasswd($id, 'passwd', 'auth3', '', 20, 72);
	$elements[] = $one;

//<script type="text/javascript" src="{$baseurl}/include/jquery.alertable.min.js"></script> N/A unless its styling can be provided
	$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/include/sjcl.js"></script>
<script type="text/javascript" src="{$baseurl}/include/auth.js"></script>
EOS;

	$jsloads[] = <<<EOS
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
//TODO $('#auth2').val() == $('#auth3').val() else error
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
  $('#auth1,#auth2,#auth3').val('');
 });
EOS;
	}
	break;

 case self::CHALLENGED:
	break;

 case self::HISEC:
	break;
} //switch level
