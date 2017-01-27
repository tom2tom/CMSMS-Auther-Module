<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
# Requires PHP 5.4+
#----------------------------------------------------------------------
namespace Auther;

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
$lang['wantjs'] = 'Enable javascript in your browser, so this will work more smoothly!';
$lang['title_login'] = 'Login/identifier';
$lang['title_email'] = 'Email address';
//$lang['password'] = 'Password'; EXISTS
$lang['title_passagain'] = 'Password (again)';
$lang['_opt'] = 'Name (optional)';
//$lang['title_name'] = 'Name'; EXISTS
$lang['_opt'] = 'Contact (optional)';
//$lang['title_contact'] = 'Contact'; EXISTS
$lang['help_contact'] = 'Typically an email address or cell/mobile phone number';
$lang[''] = 'Lost password';
$lang['title_enterdetails'] = 'Enter your details';
$lang['title_entertyped'] = 'Enter %s';

$lang['err_] = 'The password entries are not the same';
$lang['err_] = 'The password is too easy to crack';
$lang['err_] = 'The login is not available';
$lang['err_] = 'The email address is not valid';
*/

final class Setup
{
	//security-levels (TODO were in Auther.module)
	const NOBOT = 1; //captcha only
	const LOSEC = 2; //conventional login + passwd
	const NONCED = 3; //login + passwd + sync nonce
	const CHALLENGED = 4; //login + passwd + async challenge
	const HISEC = 5; //TBA non-keyed INHERENCE
	//NB in several places, NOBOT is treated as min. enum value, and HISEC as max. value
	//security-levels (per Firehed)
//    const ANONYMOUS = 0;
//    const LOGIN = 1;
//    const HISEC = 2;
	//factor-types (per Firehed)
	const KNOWLEDGE = 1; //aka KNOWN
	const POSSESSION = 2; //HELD
	const INHERENCE = 3; //BELONG ??

	protected function ErrorString(&$mod, $suffix)
	{
		$str = $mod->Lang('err_system');
		if ($suffix) {
			$str .= ': '.$suffix;
		}
		return '<p style="font-weight:bold;color:red;">'.$str.'</p>';
	}

//returns enum or FALSE
	private function CheckHandler($handler)
	{
		$type = FALSE;
		if (is_callable($handler)) { //BUT the class may have a __call() method
			if (is_array($handler && count($handler) == 2)) {
				$method = new \ReflectionMethod($handler);
				if ($method && $method->isStatic()) {
					$type = 1;
				}
			} elseif (is_string($handler) && strpos($handler,'::') !== FALSE) {
				//PHP 5.2.3+, supports passing 'ClassName::methodName'
				$method = new \ReflectionMethod($handler);
				if ($method && $method->isStatic()) {
					$type = 1;
				}
			} /* elseif (is_object($handler) && ($handler instanceof Closure)) {
				if ($this->isStatic($handler)) {
					$type = 2;
				}
			}
*/
		} elseif (is_array($handler) && count($handler) == 2) {
			$ob = \cms_utils::get_module($handler[0]);
			if ($ob) {
				$dir = $ob->GetModulePath();
				unset($ob);
				$fp = $dir.DIRECTORY_SEPARATOR.'action.'.$handler[1].'.php';
				if (@is_file($fp)) {
					$type = 3;
				} elseif (strpos($handler[1],'method.') === 0) {
					$fp = $dir.DIRECTORY_SEPARATOR.$handler[1].'.php';
					if (@is_file($fp)) {
						$type = 4;
					}
				}
			}
		} elseif (is_string($handler)) {
			if (@is_file($handler)) {
				if (substr_compare($handler,'.php',-4,4,TRUE) === 0) {
					$type = 5;
				}
			} elseif ($this->workermod->havecurl) { //curl is installed
				$config = cmsms()->GetConfig();
				$u = (empty($_SERVER['HTTPS'])) ? $config['root_url'] : $config['ssl_url'];
				$u .= '/index.php?mact=';
				$len = strlen($u);
				if (strncasecmp($u,$handler,$len) == 0) {
					$type = 6;
				}
			}
		}
		return $type;
	}

	//$elid may be FALSE
	private function GetInputText($id, $name, $elid, $size, $maxsize=FALSE)
	{
		$out = '<input type="text"';
		if ($elid) {
			$out .= ' id="'.$elid.'"';
		}
		if (!$maxsize || $maxsize < $size) {
			$maxsize = $size;
		}
		return $out.' value="" size="'.$size.'" maxlength="'.$maxsize.'" name="'.$id.$name.'" />';
	}

	//$elid may be FALSE
	private function GetInputPasswd($id, $name, $elid, $size, $maxsize=FALSE)
	{
		$out = '<input type="password" name="'.$id.$name.'"';
		if ($elid) {
			$out .= ' id="'.$elid.'"';
		}
		if (!$maxsize || $maxsize < $size) {
			$maxsize = $size;
		}
		return $out.' value="" size="'.$size.'" maxlength="'.$maxsize.'" />';
	}

	//$elid may be FALSE
	private function GetInputCheck($id, $name, $elid, $checked, $mirrored=FALSE)
	{
		if ($mirrored) {
			$out = '<input type="hidden" name="'.$id.$name.'" value="0" />'.PHP_EOL;
		} else {
			$out = '';
		}
		$out .= '<input type="checkbox" name="'.$id.$name.'"';
		if ($elid) {
			$out .= ' id="'.$elid.'"';
		}
		$out .= ' value="1"';
		if ($checked) {
			$out .= ' checked="checked"';
		}
		return $out .= ' />';
	}
/*
	private function GetInputRadio($id, $name, $elid, $choices, $labels, $first)
	{
		$out = '';
		foreach ($choices as $i=>$val) {
		}
/ *  <input type="radio" name="sex" id="radio_female" value="female" checked="checked" />
    <label for="radio_female">female</label>
    <br />
    <input type="radio" name="sex" id="radio_male" value="male" />
    <label for="radio_male">male</label>
    <br />
* /
		return $out;
	}

	private function GetInputLink($id, $name, $elid, $args)
	{
		$out = '<a></a>';
		return $out;
	}
*/
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


*/

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

	private function RegisterData(&$mod, $id, $cdata, $sdata, &$cache, &$hidden,
		&$tplary, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];
		$tplary += $components;
	}

	private function ResetData(&$mod, $id, $cdata, $sdata, &$cache, &$hidden,
		&$tplary, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];
		$tplary += $components;
	}

	private function ChangeData(&$mod, $id, $cdata, $sdata, &$cache, &$hidden,
		&$tplary, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];
		$tplary += $components;
	}

	/**
	Get:
	@context: number or alias, login-context identifier
	@task: string one of 'login','register','reset','change'
	@handler: mixed, one of
	 an array [classname,methodname] where methodname is and the method returns boolean for success
	 a string 'classname::methodname' where the method returns boolean for success
	 an array [modulename,actionname] AND the action should be a 'doer', not a 'shower', returns HTML code
	 an array [modulename,'method.whatever'] to be included, the code must conclude with variable $res = T/F indicating success
	 an URL like <server-root-url>/index.php?mact=<modulename>,cntnt01,<actionname>,0
	 	- provided the PHP curl extension is available
	 NOT a closure in a context (PHP 5.3+) OR closure (PHP 5.4+)
	 cuz those aren't transferrable between requests
	See action.TODO.php for example of a hander-action fed by a HTTP request
	 In this case too, the action should be a 'doer', and return code 200 or 400+
	@withcancel: optional boolean, whether to include a 'cancel' button, default FALSE
	@token: optional identifier passed to @handler by a previous iteration of this, default FALSE
	Returns: 2-member array:
	[0] = XHTML for inclusion in page/template, or direct echo
	[1] = js related to [0] for inclusion in page/template, or direct echo
	or upon error
	[0] = html to display an error message (partly-untranslated)
	[1] = FALSE
	*/
	public function Get($context, $task, $handler, $withcancel=FALSE, $token=FALSE)
	{
		$mod = \cms_utils::get_module('Auther');
		$utils = new Utils();
		$cid = $utils->ContextID($context);
		if ($cid === FALSE) {
			return [$this->ErrorString($mod, 'UNKNOWN CONTEXT'), FALSE];
		}

		switch ($task) {
		 case 'login':
		 case 'register':
		 case 'reset':
		 case 'change':
			break;
		 default:
			return [$this->ErrorString($mod, 'UNKNOWN TASK'), FALSE];
		}

		$htype = self::CheckHandler($handler);
		if ($htype === FALSE) {
			return [$this->ErrorString($mod, 'UNKNOWN PROCESSOR'), FALSE];
		}

		$baseurl = $mod->GetModuleURLPath();
		$jsincs = []; //script accumulators
		$jsfuncs = [];
		$jsloads = [];

		$tplvars = [];

		$config = \cmsms()->GetConfig();

		$t = $_SERVER['PHP_SELF'];
		if (strpos($t,'moduleinterface') !== FALSE) {
			$url = $baseurl.'/validate.php';
		} else {
			$t = (empty($_SERVER['HTTPS'])) ? $config['root_url'] : $config['ssl_url'];
			$url = substr($baseurl, strlen($t) + 1).'/validate.php';
		}
		$tplvars['url'] = $url;

		$tplvars['wantjs'] = $mod->Lang('wantjs');

		$jsloads[] = <<<EOS
 $('.hidejs').css('display','none');
EOS;
		$db = \cmsms()->GetDb();
		$pre = \cms_db_prefix();
		$cdata = $db->GetRow('SELECT * FROM '.$pre.'module_auth_contexts WHERE id=?', [$cid]);

		if ($token) {
			$sdata = []; //TODO cached sessiondata
		} else {
			$sdata = FALSE;
		}

		$iv = $utils->RandomAlnum(8); //sized for Blowfish in openssl
		$now = time();
		$base = floor($now / (84600 * 1800)) * 1800; //start of current 30-mins
		$day = date('j',$now);
		$id = $iv[2].$iv[3].$utils->Tokenise($base+$day).'_'; //6-bytes

		$hidden = [
		$mod->CreateInputHidden($id, 'jsworks', ''),
		$mod->CreateInputHidden($id, 'IV', $iv)
		];

		$cache = [
		'context' => $cid,
		'handler' => $handler,
		'handlertype' => $htype,
		'identity' => substr($id, 2, 3),
		'task' => $task,
		'token' => $token,
		];

		$jsloads[] = <<<EOS
 $('#{$id}jsworks').val('OK');
EOS;

		$tplary = [];

		switch ($task) {
		 case 'login':
			self::LoginData   ($mod,$id,$cdata,$sdata,$cache,$hidden,$tplary,$jsincs,$jsfuncs,$jsloads);
			break;
		 case 'register':
			self::RegisterData($mod,$id,$cdata,$sdata,$cache,$hidden,$tplary,$jsincs,$jsfuncs,$jsloads);
			break;
		 case 'reset':
			self::ResetData   ($mod,$id,$cdata,$sdata,$cache,$hidden,$tplary,$jsincs,$jsfuncs,$jsloads);
			break;
		 case 'change':
			self::ChangeData  ($mod,$id,$cdata,$sdata,$cache,$hidden,$tplary,$jsincs,$jsfuncs,$jsloads);
			break;
		}

		$cfuncs = new Crypter();
		$pw = $cfuncs->decrypt_preference($mod, 'masterpass');
		$t = openssl_encrypt(json_encode($cache), 'BF-CBC', $pw, 0, $iv); //low security
		$hidden[] = $mod->CreateInputHidden($id, 'data', $t);

		$tplvars['hidden'] = implode(PHP_EOL,$hidden);
		$tplvars['components'] = $tplary;
		$tplvars['submitbtn'] =
'<input type="submit" id="authsend" name="'.$id.'send" value="'.$mod->Lang('submit').'" />';
		if ($withcancel && 0) { //TODO special-cases
			$withcancel = FALSE;
		}
		if ($withcancel) {
			$tplvars['cancelbtn'] =
'<input type="submit" id="authcancel" name="'.$id.'cancel" value="'.$mod->Lang('cancel').'" />';
		}

		$jsloads[] = <<<'EOS'
 $('#focus')[0].focus();
EOS;

		$tplstr = <<<'EOS'
<div id="authcontainer">
 <div class="hidejs">
  <p class="authtitle" style="color:red;">{$wantjs}</p>
  <br />
 </div>
{if (!empty($intro))}<p class="authtext">{$intro}</p><br />{/if}
 <form action="{$url}" method="POST" enctype="multipart/form-data">
  <div style="display:none;">
{$hidden}
  </div>
  <div id="authelements">
{foreach from=$components item='elem' name='opts'}
{if !empty($elem->title)}<p class="authtitle">{$elem->title}</p>{/if}
{if !empty($elem->input)}<div class="authinput">{$elem->input}</div>{/if}
{if !empty($elem->extra)}<div class="authtext">{$elem->extra}</div>{/if}
{if !$smarty.foreach.opts.last}<br />{/if}
{/foreach}
  </div>
  <div id="authactions">
 {$submitbtn}{if !empty($cancelbtn)} {$cancelbtn}{/if}
  </div>
 </form>
{if (!empty($after))}<br /><p class="authtext">{$after}</p>{/if}
</div>
EOS;
		$out = $utils->ProcessTemplateFromData($mod,$tplstr,$tplvars);
		$jsall = $utils->MergeJS($jsincs,$jsfuncs,$jsloads);
		return [$out,$jsall];
	}
}
