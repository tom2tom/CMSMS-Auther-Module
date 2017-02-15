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
	/**
	ContextID:
	Get identifier (number) for @context
	@context: identifier number|alias|name
	Returns: int or FALSE
	*/
	public function ContextID($context)
	{
		$pre = \cms_db_prefix();
		$sql = 'SELECT id FROM '.$pre.'module_auth_contexts WHERE id=? OR name=? or alias=?';
		$db = \cmsms()->GetDB();
		$id = $db->GetOne($sql, [(int)$context,$context,$context]);
		if ($id || is_numeric($id)) { //default context 0 is ok
			return (int)$id;
		}
		return FALSE;
	}

	/**
	ContextName:
	Get identifier (name) for @context
	@context: identifier number|alias|name
	Returns: string or FALSE
	*/
	public function ContextName($context)
	{
		$pre = \cms_db_prefix();
		$sql = 'SELECT name FROM '.$pre.'module_auth_contexts WHERE id=? OR name=? or alias=?';
		$db = \cmsms()->GetDB();
		return $db->GetOne($sql, [(int)$context,$context,$context]);
	}

	/**
	DeleteContext:
	@context: numeric context identifier, or array of them
	*/
	public function DeleteContext($context)
	{
		$pre = \cms_db_prefix();
		if (is_array($context)) {
			$i = array_search(0, $context);
			if ($i !== FALSE) {
				unset($context[$i]); //preserve default context
				if (!$context) {
					return;
				}
			}
			$fillers = str_repeat('?,', count($context)-1);
			$sql1 = 'DELETE FROM '.$pre.'module_auth_users WHERE context_id IN ('.$fillers.'?)';
			$sql2 = 'DELETE FROM '.$pre.'module_auth_contexts WHERE id IN ('.$fillers.'?)';
			$args = $context;
		} else {
			if ($context === 0) {
				return; //preserve default
			}
			$sql1 = 'DELETE FROM '.$pre.'module_auth_users WHERE context_id=?';
			$sql2 = 'DELETE FROM '.$pre.'module_auth_contexts WHERE id=?';
			$args = [$context];
		}
		$db = \cmsms()->GetDB();
		$db->Execute($sql1, $args);
		$db->Execute($sql2, $args);
	}

	/**
	DeleteContextUsers:
	@context: numeric context identifier, or array of them
	*/
	public function DeleteContextUsers($context)
	{
		$pre = \cms_db_prefix();
		if (is_array($context)) {
			$fillers = str_repeat('?,', count($context)-1);
			$sql = 'DELETE FROM '.$pre.'module_auth_users WHERE context_id IN ('.$fillers.'?)';
			$args = $context;
		} else {
			$sql = 'DELETE FROM '.$pre.'module_auth_users WHERE context_id=?';
			$args = [$context];
		}
		$db = \cmsms()->GetDB();
		$db->Execute($sql, $args);
	}

	/**
	DeleteUser:
	For admin use, c.f. Auth::cancelUser(), which includes password verification
	@user: numeric user identifier, or array of them
	*/
	public function DeleteUser($user)
	{
		$pre = \cms_db_prefix();
		if (is_array($user)) {
			$fillers = str_repeat('?,', count($user)-1);
			$sql = 'DELETE FROM '.$pre.'module_auth_users WHERE id IN ('.$fillers.'?)';
			$args = $user;
		} else {
			$sql = 'DELETE FROM '.$pre.'module_auth_users WHERE id=?';
			$args = [$user];
		}
		$db = \cmsms()->GetDB();
		$db->Execute($sql, $args);
	}

	/**
	Tokenise:
	@$num: integer
	Returns: 3-byte token derived from @num
	*/
	public function Tokenise($num)
	{
		//djb2a hash : see http://www.cse.yorku.ca/~oz/hash.html
		$n = ''.$num;
		$l = strlen($n);
		$hash = 5381;
		for ($i = 0; $i < $l; $i++) {
			$hash = ($hash + ($hash << 5)) ^ $n[$i]; //aka $hash = $hash*33 ^ $n[$i]
		}
		return substr($hash, -3);
	}

	/**
	RandomString:
	Generate a pseudo-random ASCII string of the specified length
	@length: int wanted byte-count
	@alnum: optional boolean, whether to limit the string to numbers and (english) lettters, default TRUE
	@letterfirst: optional boolean, whether to force the first char to be a letter, default FALSE
	Returns: string
	*/
	public function RandomString($length, $alnum=TRUE, $letterfirst=FALSE)
	{
		$chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz';
		if (!$alnum) {
			$chars .= '~!@#$%^&*<>[]{}()-+,.?|/\\';
		}
		$cl = strlen($chars) - 1;

		$ret = str_repeat('0', $length);
		for ($i = 0; $i < $length; $i++) {
			$ret[$i] = $chars[mt_rand(0, $cl)];
			if ($i == 0 && $letterfirst) {
				if (!preg_match('/[A-Za-z]/',$ret[$i])) {
					$i--; //start again
				}
			}
		}
		return $ret;
	}

	/**
	BuildNav:
	Generate XHTML page-change links for admin action
	@mod: reference to current module-object
	@id: session identifier
	@returnid:
	@params: reference to array of request-parameters including link-related data
	Returns: nothing
	*/
	public function BuildNav(&$mod, $id, $returnid, &$params)
	{
		$navstr = $mod->CreateLink($id, 'defaultadmin', $returnid,
		'&#171; '.$mod->Lang('module_nav'));
		//TODO
		if ($params['action'] == 'openuser') {
			$navstr .= ' '.$mod->CreateLink($id, 'users', $returnid,
			'&#171; '.$mod->Lang('users'), [
			'ctx_id'=>$params['ctx_id'],
			'edit'=>$params['edit']]);
		}
		return $navstr;
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
	MergeJS:
	@jsincs: array of js include directives, or FALSE
	@jsfuncs: array of js to be included outside jQuery document.ready function, or FALSE
	@jsloads: array of js to be included in jQuery document.ready function, or FALSE
	Returns: js string
	*/
	public function MergeJS($jsincs, $jsfuncs, $jsloads)
	{
		if (is_array($jsincs)) {
			$all = $jsincs;
		} elseif ($jsincs) {
			$all = [$jsincs];
		} else {
			$all = [];
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
//			$funcs = new JSqueeze();
//			$all[] = $funcs->squeeze(implode(PHP_EOL, $all2));
			$all[] =<<<'EOS'
//]]>
</script>
EOS;
		}
		return implode(PHP_EOL, $all);
	}

	/**
	ProcessTemplate:
	@mod: reference to current Auther module object
	@tplname: template identifier
	@tplvars: associative array of template variables
	@cache: optional boolean, default TRUE
	Returns: string, processed template
	*/
	public function ProcessTemplate(&$mod, $tplname, $tplvars, $cache=TRUE)
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
	public function ProcessTemplateFromData(&$mod, $data, $tplvars)
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
}
