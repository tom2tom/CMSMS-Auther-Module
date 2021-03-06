<?php
#-----------------------------------------------------------------------
# CMS Made Simple module: Auther (C) 2017 Tom Phane
# Allows other modules to check/set user authentication
#-----------------------------------------------------------------------
# CMS Made Simple (C) 2004-2017 Ted Kulp (wishy@cmsmadesimple.org)
# Its homepage is: http://www.cmsmadesimple.org
#-----------------------------------------------------------------------
# This module is free software; you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This module is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# Read it online at http://www.gnu.org/licenses/licenses.html#AGPL
#-----------------------------------------------------------------------

if (!extension_loaded('openssl')) return;

class Auther extends CMSModule
{
	const LENSHORTVAL = 64;
	//security-levels (replicated in class.Setup)
	const NOBOT = 1; //captcha only
	const LOSEC = 2; //conventional login + passwd
	const MIDSEC = 3; //login + passwd + sync nonce
	const CHALLENGED = 4; //login + passwd + async challenge
	const HISEC = 5; //TBA non-keyed INHERENCE
	//NB ordinal: in several places, NOBOT is treated as min. enum value, and HISEC as max. value

	public $before20;
	public $oldtemplates;
	public $sendMail;
	public $sendSMS;

	public function __construct()
	{
		parent::__construct();
		global $CMS_VERSION;
		$this->before20 = (version_compare($CMS_VERSION, '2.0') < 0);
		$this->oldtemplates = $this->before20 || 1; //TODO
		if ($this->before20) {
			$ob = cms_utils::get_module('CMSMailer');
			if ($ob) {
				unset($ob);
				$this->sendMail = TRUE;
			} else {
				$this->sendMail = FALSE;
			}
		} else {
			$this->sendMail = TRUE;
		}
		$ob = cms_utils::get_module('SMSG');
		if ($ob) {
			unset($ob);
			$this->sendSMS = TRUE;
		} else {
			$this->sendSMS = FALSE;
		}

		spl_autoload_register([$this, 'cmsms_spacedload']);
	}

	public function __destruct()
	{
		spl_autoload_unregister([$this, 'cmsms_spacedload']);
		if (function_exists('parent::__destruct')) {
			parent::__destruct();
		}
	}

	/* namespace autoloader - CMSMS default autoloader doesn't do spacing */
	private function cmsms_spacedload($class)
	{
		$prefix = get_class().'\\'; //our namespace prefix
		$o = ($class[0] != '\\') ? 0:1;
		$p = strpos($class, $prefix, $o);
		if ($p === 0 || ($p == 1 && $o == 1)) {
			// directory for the namespace
			$bp = __DIR__.DIRECTORY_SEPARATOR.'lib'.DIRECTORY_SEPARATOR;
		} elseif (($p = strpos($class, 'ZxcvbnPhp\\', $o)) === 0 || ($p == 1 && $o == 1)) {
			$parts = explode('\\',$class);
			$fn = array_pop($parts);
			$fp = __DIR__.DIRECTORY_SEPARATOR.'lib'.DIRECTORY_SEPARATOR
				.implode(DIRECTORY_SEPARATOR,$parts).DIRECTORY_SEPARATOR
				.$fn.'.php';
			if (@file_exists($fp)) {
				include $fp;
			}
			return;
		} else {
			$p = strpos($class, '\\', 1);
			if ($p === FALSE) {
				return;
			}
			$prefix = substr($class, $o, $p-$o);
			$bp = dirname(__DIR__).DIRECTORY_SEPARATOR.$prefix.DIRECTORY_SEPARATOR.'lib'.DIRECTORY_SEPARATOR;
		}
		// relative class name
		$len = strlen($prefix) + $o;
		$relative_class = trim(substr($class, $len), '\\');

		if (($p = strrpos($relative_class, '\\', -1)) !== FALSE) {
			$relative_dir = strtr ($relative_class, '\\', DIRECTORY_SEPARATOR);
			$bp .= substr($relative_dir, 0, $p+1);
			$base = substr($relative_dir, $p+1);
		} else {
			$base = $relative_class;
		}

		$fp = $bp.'class.'.$base.'.php';
		if (file_exists($fp)) {
			include $fp;
			return;
		}
		$fp = $bp.$base.'.php';
		if (file_exists($fp)) {
			include $fp;
		}
	}

	public function GetAdminDescription()
	{
		return $this->Lang('admindescription');
	}

	public function GetAdminSection()
	{
		return 'extensions';
	}

	public function GetAuthor()
	{
		return 'Tom Phane';
	}

	public function GetAuthorEmail()
	{
		return 'tpgww@onepost.net';
	}

	public function GetFriendlyName()
	{
		return $this->Lang('friendlyname');
	}

	public function GetName()
	{
		return 'Auther';
	}

	public function GetVersion()
	{
		return '0.2';
	}

	public function HasAdmin()
	{
		return TRUE;
	}

	public function InstallPostMessage()
	{
		return $this->Lang('postinstall');
	}
//	public function IsPluginModule()	{ return FALSE; }
//	public function MaximumCMSVersion()	{ return 'X' }

	public function MinimumCMSVersion()
	{
		return '1.10';
	}

	public function UninstallPostMessage()
	{
		return $this->Lang('postuninstall');
	}

	public function UninstallPreMessage()
	{
		return $this->Lang('really_uninstall');
	}
	//for 1.11+
	public function AllowSmartyCaching()
	{
		return FALSE;
	}

	public function LazyLoadAdmin()
	{
		return TRUE;
	}

	public function LazyLoadFrontend()
	{
		return TRUE;
	}

	public function GetChangeLog()
	{
		return ''.@file_get_contents(cms_join_path(__DIR__,'lib','doc','changelog.htm'));
	}

	public function GetDependencies()
	{
		if ($this->before20) {
			return ['CMSMailer'=>'1.0'];
		} else {
			return [];
		}
	}

	public function GetHelp()
	{
		$fn = cms_join_path(__DIR__,'css','authpanel.css');
		$cont = @file_get_contents($fn);
		if ($cont) {
			$example = preg_replace(array('~\s?/\*(.*)?\*/~Usm','~\s?//.*$~m'),array('',''),$cont);
			$example = str_replace(array("\n\n","\n","\t"),array('<br />','<br />',' '),trim($example));
		} else {
			$example = 'MISSING!';
		}
		$cont = ''.@file_get_contents(cms_join_path(__DIR__,'lib','doc','modhelp.htm'));
		return sprintf($cont,$example);
	}

	public function VisibleToAdminUser()
	{
		return $this->_CheckAccess();
	}

	public function GetHeaderHTML()
	{
		$baseurl = $this->GetModuleURLPath();
		//authpanel included for debugging
		return <<<EOS
<link rel="stylesheet" type="text/css" href="{$baseurl}/css/alertable.css" />
<link rel="stylesheet" type="text/css" id="adminstyler" href="{$baseurl}/css/admin.css" />
<link rel="stylesheet" type="text/css" href="{$baseurl}/css/authpanel.css" />
EOS;
	}

	public function SetParameters()
	{
		$this->InitializeAdmin();
//		$this->InitializeFrontend ();
	}

	public function InitializeAdmin()
	{
		//this is needed to block construct-time circularity
	}

/*public function InitializeFrontend()
	{
		//pretty-url support is deprecated - better to not involve frontend
		//all of this can go, when support is removed
		$this->RestrictUnknownParams();
		$this->SetParameterType('showtemplate',CLEAN_STRING);
		$rid = cmsms()->GetContentOperations()->GetDefaultPageID();
		$this->RegisterRoute('/[Aa]uther\/([a-zA-Z0-9_-]+)(\/.*?)?$/',
			['action' => 'TODO',
				'showtemplate' => 'FALSE', //NOT FALSE or any of its equivalents
				'returnid' => $rid
			]);
	}
*/
	public function GetEventDescription($eventname)
	{
		if (strncmp($eventname, 'Auth', 4) === 0) {
			$key = 'event_'.substr($eventname, 4).'_desc';
			return $this->Lang($key);
		}
		return '';
	}

	public function GetEventHelp($eventname)
	{
		if (strncmp($eventname, 'Auth', 4) === 0) {
			$key = 'event_'.substr($eventname, 4).'_help';
			return $this->Lang($key);
		}
		return '';
	}

	/*
	get_tasks:
	Specify the tasks that this module uses
	Returns: CmsRegularTask-compliant object, or array of them
	*/
/*	public function get_tasks()
	{
		return [
			new Auther\Cleanold_task(),
//			new Auther\Clearcache_task()
		];
	}
*/
	/**
	_CheckAccess:
	NOT PART OF THE MODULE API
	@permission default=''
	@warn whether to echo error message, default=FALSE
	*/
	public function _CheckAccess($permission='', $warn=FALSE)
	{
		switch ($permission) {
		 case '': //anything relevant
			$name = '';
			$ok = $this->CheckPermission('AuthModuleAdmin');
			if (!$ok) $ok = $this->CheckPermission('AuthModifyContext');
			if (!$ok) $ok = $this->CheckPermission('AuthModifyUser');
			if (!$ok) $ok = $this->CheckPermission('AuthView');
			break;
		 case 'view':
			$name = 'AuthView';
			$ok = $this->CheckPermission($name);
			break;
		 case 'admin':
			$name = 'AuthModuleAdmin';
			$ok = $this->CheckPermission($name);
			break;
		 case 'context':
			$name = 'AuthModifyContext';
			$ok = $this->CheckPermission($name);
			break;
		 case 'user':
			$name = 'AuthModifyUser';
			$ok = $this->CheckPermission($name);
			break;
		 default:
			$name = '';
			$ok = FALSE;
		}
		if (!$ok && $warn) {
			if ($name == '') $name = $this->Lang('perm_some');
			echo '<p class="error">'.$this->Lang('accessdenied',$name).'</p>';
		}
		return $ok;
	}
}
