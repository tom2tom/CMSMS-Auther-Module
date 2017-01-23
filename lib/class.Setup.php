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
	//returns enum or FALSE
	private static function CheckHandler($handler)
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

	//returns 3-byte token
	private static function Hash($num)
	{
		//djb2 hash : see http://www.cse.yorku.ca/~oz/hash.html
		$n = ''.$num;
		$l = strlen($n);
		$hash = 5381;
		for ($i = 0; $i < $l; $i++) {
			$hash += $hash + ($hash << 5) + $n[$i]; //aka $hash = $hash*33 + $n[$i]
		}
		return substr($hash, -3);
	}

	private static function LoginData(&$mod, $id, $cdata, $withcancel, $token,
		&$data, &$hidden, &$tplvars, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];

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
		$oneset->input = str_replace('id="'.$id,'id="',$t);
		if (0) {
//			$onset->extra = ;
		}
		$components[] = $oneset;

//		repeat ...


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
		return $components;
	}

	private static function RegisterData(&$mod, $id, $cdata, $withcancel, $token,
		&$data, &$hidden, &$tplvars, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];
		return $components;
	}

	private static function ResetData(&$mod, $id, $cdata, $withcancel, $token,
		&$data, &$hidden, &$tplvars, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];
		return $components;
	}

	private static function ChangeData(&$mod, $id, $cdata, $withcancel, $token,
		&$data, &$hidden, &$tplvars, &$jsincs, &$jsfuncs, &$jsloads)
	{
		$components = [];
		return $components;
	}

	/**
	Get:
	@context: number or alias, login-context identifier
	@task: string one of 'login','register','reset','change'
	@handler: mixed, one of
	 an array [classname,methodname] where methodname is static and the method returns boolean for success
	 a string 'classname::methodname' where the method returns boolean for success
	 an array [modulename,actionname] AND the action should be a 'doer', not a 'shower', returns HTML code
	 an array [modulename,'method.whatever'] to be included, the code must conclude with variable $res = T/F indicating success
	 an URL like <server-root-url>/index.php?mact=<modulename>,cntnt01,<actionname>,0
	 	- provided the PHP curl extension is available
	 NOT a closure in a static context (PHP 5.3+) OR static closure (PHP 5.4+)
	 cuz those aren't transferrable between requests
	See action.TODO.php for example of a hander-action fed by a HTTP request
	 In this case too, the action should be a 'doer', and return code 200 or 400+
	@withcancel: optional boolean, whether to include a 'cancel' button, default FALSE
	@token: optional identifier passed to @handler by a previous iteration of this, default FALSE
	Returns: 2-member array:
	[0] = XHTML for inclusion in page/template, or direct echo
	[1] = js related to [0] for inclusion in page/template, or direct echo
	or upon error
	[0] = FALSE
	[1] = error message for internal use (untranslated)
	*/
	public static function Get($context, $task, $handler, $withcancel=FALSE, $token=FALSE)
	{
		$utils = new Utils();
		$cid = $utils->ContextID($context);
		if ($cid === FALSE) {
			return [FALSE,'UNKNOWN CONTEXT'];
		}

		switch ($task) {
		 case 'login':
		 case 'register':
		 case 'reset':
		 case 'change':
			break;
		 default:
			return [FALSE,'UNKNOWN TASK'];
		}

		$htype = self::CheckHandler($handler);
		if ($htype === FALSE) {
			return [FALSE,'UNKNOWN PROCESSOR'];
		}

		$mod = \cms_utils::get_module('Auther');
		$baseurl = $mod->GetModuleURLPath();
		$jsincs = []; //script accumulators
		$jsfuncs = [];
		$jsloads = [];

		$tplvars = [];

		$config = \cmsms()->GetConfig();
		$t = (empty($_SERVER['HTTPS'])) ? $config['root_url'] : $config['ssl_url'];
		$url = substr($baseurl,strlen($t)+1).'/validate.php';
		$tplvars['startform'] = '<form action="'.$url.'" method="POST">';

		$tplvars['wantjs'] = $mod->Lang('wantjs');

		$jsloads[] = <<<EOS
 $('.hidejs').css('display','none');
EOS;
		$db = \cmsms()->GetDb();
		$pre = \cms_db_prefix();
		$cdata = $db->GetRow('SELECT * FROM '.$pre.'module_auth_contexts WHERE id=?', [$cid]);

		$now = time();
		$base = floor($now / (84600 * 1800)) * 1800; //start of current 30-mins
		$day = date('j',$now);
		$id = $utils->RandomAlnum(3).self::Hash($base+$day).'_';

		$cfuncs = new Crypter();

		$data = [];
		$hidden = [];
		$hidden[] = $mod->CreateInputHidden($id, 'context', $cid);
		$hidden[] = $mod->CreateInputHidden($id, 'handler', $cfuncs->fusc($id.'|'.$htype.'|'.json_encode($handler)));
		$hidden[] = $mod->CreateInputHidden($id, 'identity', $id);
		$hidden[] = $mod->CreateInputHidden($id, 'token', '');

		switch ($task) {
		 case 'login':
			self::LoginData($mod,$id,$cdata,$withcancel,$token,$data,$hidden,$tplvars,$jsincs,$jsfuncs,$jsloads);
			break;
		 case 'register':
			self::RegisterData($mod,$id,$cdata,$withcancel,$token,$data,$hidden,$tplvars,$jsincs,$jsfuncs,$jsloads);
			break;
		 case 'reset':
			self::ResetData($mod,$id,$cdata,$withcancel,$token,$data,$hidden,$tplvars,$jsincs,$jsfuncs,$jsloads);
			break;
		 case 'change':
			self::ChangeData($mod,$id,$cdata,$withcancel,$token,$data,$hidden,$tplvars,$jsincs,$jsfuncs,$jsloads);
			break;
		}

		$tlpvars['hidden'] = implode(PHP_EOL,$hidden);
		$tplvars['components'] = $data;

		$tplvars['submitbtn'] =
'<input type="submit" id="authsend" name="'.$id.'send" value="'.$mod->Lang('submit').'" />';
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
 {$startform}
  <div style="display:none;">
{$hidden}
  </div>
  <div id="authelements">
{foreach from=$components item='elem' name='opts'}
{if !empty($elem->title)}<p class="authtitle">{$elem->title}</p>{/if}
{if !empty($elem->input)}<p class="authinput">{$elem->input}</p>{/if}
{if !empty($elem->extra)}<div class="authtext">{$elem->>extra}</div>{/if}
{if !smarty.foreach.opts.last}<br />{/if}
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
		$jsall = $utils->JSMerge($jsincs,$jsfuncs,$jsloads);
		return [$out,$jsall];
	}
}
