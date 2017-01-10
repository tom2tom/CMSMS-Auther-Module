<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
namespace Auther;

class Utils
{
	public function fusc($str)
	{
		if ($str) {
			$s = substr(base64_encode(md5(microtime())), 0, 5);
			return $s.base64_encode($s.$str);
		}
		return '';
	}

	public function unfusc($str)
	{
		if ($str) {
			$s = base64_decode(substr($str, 5));
			return substr($s, 5);
		}
		return '';
	}

	/**
	@mod: reference to current Auther module object
	*/
	public function encrypt_value(&$mod, $value, $passwd=FALSE)
	{
		if ($value) {
			if ($mod->havemcrypt) {
				if (!$passwd) {
					$passwd = $mod->GetPreference('pref_masterpass');
					if ($passwd) {
						$passwd = self::unfusc($passwd);
					}
				}
				if ($passwd) {
					$e = new Auther\Encryption(\MCRYPT_BLOWFISH, \MCRYPT_MODE_CBC, 10);
					$value = $e->encrypt($value, $passwd);
				}
			}
		}
		return $value;
	}

	/**
	@mod: reference to current Auther module object
	*/
	public function decrypt_value(&$mod, $value, $passwd=FALSE)
	{
		if ($value) {
			if ($mod->havemcrypt) {
				if (!$passwd) {
					$passwd = $mod->GetPreference('pref_masterpass');
					if ($passwd) {
						$passwd = self::unfusc($passwd);
					}
				}
				if ($passwd) {
					$e = new Auther\Encryption(\MCRYPT_BLOWFISH, \MCRYPT_MODE_CBC, 10);
					$value = $e->decrypt($value, $passwd);
				}
			}
		}
		return $value;
	}

	/**
	BuildNav:
	Generate XHTML page-change links for admin action
	@mod: reference to current module-object
	@id: session identifier
	@returnid:
	@params: reference to array of request-parameters including link-related data
	@tplvars: reference to associative array of template variables
	Returns: nothing
	*/
	public function BuildNav(&$mod, $id, $returnid, &$params, &$tplvars)
	{
		$navstr = $mod->CreateLink($id, 'defaultadmin', $returnid,
		'&#171; '.$mod->Lang('module_nav'));
		//TODO
		if (X) {
			$navstr .= ' '.$mod->CreateLink($id, 'users', $returnid,
			'&#171; '.$mod->Lang('users'), array(
			'context_id'=>$params['context_id'],
			'edit'=>$params['edit']));
		}
		$tplvars['inner_nav'] = $navstr;
	}

	/**
	PrettyMessage:
	@mod: reference to current module-object
	@text: text to display, or if @key = TRUE, a lang-key for the text to display
	@success: optional default TRUE whether to style message as positive
	@key: optional default TRUE whether @text is a lang key or raw
	*/
	public function PrettyMessage(&$mod, $text, $success=TRUE, $key=TRUE)
	{
		$base = ($key) ? $mod->Lang($text) : $text;
		if ($success)
			return $mod->ShowMessage($base);
		else {
			$msg = $mod->ShowErrors($base);
			//strip the link
			$pos = strpos($msg,'<a href=');
			$part1 = ($pos !== FALSE) ? substr($msg,0,$pos) : '';
			$pos = strpos($msg,'</a>',$pos);
			$part2 = ($pos !== FALSE) ? substr($msg,$pos+4) : $msg;
			$msg = $part1.$part2;
			return $msg;
		}
	}

	/**
	ProcessTemplate:
	@mod: reference to current Auther module object
	@tplname: template identifier
	@tplvars: associative array of template variables
	@cache: optional boolean, default TRUE
	Returns: string, processed template
	*/
	public static function ProcessTemplate(&$mod, $tplname, $tplvars, $cache=TRUE)
	{
		global $smarty;
		if ($mod->before20) {
			$smarty->assign($tplvars);
			return $mod->ProcessTemplate($tplname);
		} else {
			if ($cache) {
				$cache_id = md5('bkr'.$tplname.serialize(array_keys($tplvars)));
				$lang = \CmsNlsOperations::get_current_language();
				$compile_id = md5('bkr'.$tplname.$lang);
				$tpl = $smarty->CreateTemplate($mod->GetFileResource($tplname), $cache_id, $compile_id, $smarty);
				if (!$tpl->isCached()) {
					$tpl->assign($tplvars);
				}
			} else {
				$tpl = $smarty->CreateTemplate($mod->GetFileResource($tplname), NULL, NULL, $smarty, $tplvars);
			}
			return $tpl->fetch();
		}
	}

	/**
	ProcessTemplateFromData:
	@mod: reference to current Auther module object
	@data: string
	@tplvars: associative array of template variables
	No cacheing.
	Returns: string, processed template
	*/
	public static function ProcessTemplateFromData(&$mod, $data, $tplvars)
	{
		global $smarty;
		if ($mod->before20) {
			$smarty->assign($tplvars);
			return $mod->ProcessTemplateFromData($data);
		} else {
			$tpl = $smarty->CreateTemplate('eval:'.$data, NULL, NULL, $smarty, $tplvars);
			return $tpl->fetch();
		}
	}

	public function MergeJS($jsincs, $jsfuncs, $jsloads, &$merged)
	{
		if (is_array($jsincs)) {
			$all = $jsincs;
		} elseif ($jsincs) {
			$all = array($jsincs);
		} else {
			$all = array();
		}
		if ($jsfuncs || $jsloads) {
			$all[] =<<<'EOS'
<script type="text/javascript">
//<![CDATA[
EOS;
			if (is_array($jsfuncs)) {
				$all = array_merge($all, $jsfuncs);
			} elseif ($jsfuncs) {
				$all[] = $jsfuncs;
			}
			if ($jsloads) {
				$all[] =<<<'EOS'
$(document).ready(function() {
EOS;
				if (is_array($jsloads)) {
					$all = array_merge($all, $jsloads);
				} else {
					$all[] = $jsloads;
				}
				$all[] =<<<'EOS'
});
EOS;
			}
			$all[] =<<<'EOS'
//]]>
</script>
EOS;
		}
		$merged = implode(PHP_EOL, $all);
	}
}
