<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
# Requires PHP 5.4+
#----------------------------------------------------------------------
namespace Auther;

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

	private function ErrorString(&$mod, $suffix)
	{
		$str = $mod->Lang('err_system');
		if ($suffix) {
			$str .= ': '.$suffix;
		}
		return '<p style="font-weight:bold;color:red;">'.$str.'</p>';
	}

	//Returns: enum or FALSE
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

	//$elid, $value may be FALSE
	private function GetInputText($id, $name, $elid, $value, $size, $maxsize=FALSE)
	{
		$out = '<input type="text"';
		if ($elid) {
			$out .= ' id="'.$elid.'"';
		}
		if (!$maxsize || $maxsize < $size) {
			$maxsize = $size;
		}
		return $out.' value="'.$value.'" size="'.$size.'" maxlength="'.$maxsize.'" name="'.$id.$name.'" />';
	}

	//$elid, $value may be FALSE
	private function GetInputPasswd($id, $name, $elid, $value, $size, $maxsize=FALSE)
	{
		$out = '<input type="password"';
		if ($elid) {
			$out .= ' id="'.$elid.'"';
		}
		if (!$maxsize || $maxsize < $size) {
			$maxsize = $size;
		}
		return $out.' value="'.$value.'" size="'.$size.'" maxlength="'.$maxsize.'" name="'.$id.$name.'" />';
	}

	//$elid may be FALSE
	private function GetInputCheck($id, $name, $elid, $checked, $mirrored=FALSE)
	{
		if ($mirrored) {
			$out = '<input type="hidden" value="0" name="'.$id.$name.'" />'.PHP_EOL;
		} else {
			$out = '';
		}
		$out .= '<input type="checkbox"';
		if ($elid) {
			$out .= ' id="'.$elid.'"';
		}
		$out .= ' value="1"';
		if ($checked) {
			$out .= ' checked="checked"';
		}
		return $out .= ' name="'.$id.$name.'" />';
	}

/*	private function GetInputRadio($id, $name, $elid, $choices, $labels, $first)
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
 var el = $('#focus');
 if (el.length) {
   el[0].focus();
 }
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

		$cache = [
		'context' => $cid,
		'handler' => $handler,
		'handlertype' => $htype,
		'identity' => substr($id, 2, 3),
		'task' => $task,
		'token' => $token,
		];

		$hidden = [$mod->CreateInputHidden($id, 'jsworks', '')];
		$jsloads[] = <<<EOS
 $('#{$id}jsworks').val('$iv');
EOS;

		$elements = [];
		//append as appropriate to arrays: $cache, $hidden, $elements, $tplvars, $jsincs, $jsfuncs, $jsloads
		require __DIR__.DIRECTORY_SEPARATOR.'method.'.$task.'.php';

		$cfuncs = new Crypter();
		$pw = $cfuncs->decrypt_preference($mod, 'masterpass');
		$t = openssl_encrypt(json_encode($cache), 'BF-CBC', $pw, 0, $iv); //low security
		$hidden[] = $mod->CreateInputHidden($id, 'IV', $iv);
		$hidden[] = $mod->CreateInputHidden($id, 'data', $t);

		$tplvars['hidden'] = implode(PHP_EOL,$hidden);
		$tplvars['components'] = $elements;
		$tplvars['submitbtn'] =
'<input type="submit" id="authsend" name="'.$id.'send" value="'.$mod->Lang('submit').'" />';
		if ($withcancel && 0) { //TODO special-cases
			$withcancel = FALSE;
		}
		if ($withcancel) {
			$tplvars['cancelbtn'] =
'<input type="submit" id="authcancel" name="'.$id.'cancel" value="'.$mod->Lang('cancel').'" />';
		}

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
{foreach from=$components item='elem'}
{if !empty($elem->title)}<p class="authtitle">{$elem->title}</p>{/if}
{if !empty($elem->input)}<div class="authinput">{$elem->input}</div>{/if}
{if !empty($elem->extra)}<div class="authtext">{$elem->extra}</div>{/if}
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
