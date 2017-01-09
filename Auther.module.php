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

class Auther extends CMSModule
{
	//security-levels (per Firehed)
    const ANONYMOUS = 0;
    const LOGIN = 1;
    const HISEC = 2;
	//factor-types (per Firehed)
	const KNOWLEDGE = 1;
	const POSSESSION = 2;
	const INHERENCE = 3;

	public $before20;

	public function __construct()
	{
		parent::__construct();
		global $CMS_VERSION;
		$this->before20 = (version_compare($CMS_VERSION, '2.0') < 0);

		spl_autoload_register(array($this, 'auther_spacedload'));
	}

	public function __destruct()
	{
		spl_autoload_unregister(array($this, 'auther_spacedload'));
		if (function_exists('parent::__destruct')) {
			parent::__destruct();
		}
	}

	private function auther_spacedload($class)
	{
		$prefix = get_class().'\\'; //our namespace prefix
		$p = strpos($class, $prefix);
		if (!($p === 0 || ($p === 1 && $class[0] == '\\') || $p === FALSE)) {
			return;
		}
		// get the relative class name
		if ($p !== FALSE) {
			$len = strlen($prefix);
			if ($p == 1) {
				$len++;
			}
			$relative_class = trim(substr($class, $len), '\\');
		} else {
			$relative_class = trim($class, '\\');
		}
		if (($p = strrpos($relative_class, '\\', -1)) !== FALSE) {
			$relative_dir = str_replace('\\', DIRECTORY_SEPARATOR, $relative_class);
			$base = substr($relative_dir, $p+1);
			$relative_dir = substr($relative_dir, 0, $p).DIRECTORY_SEPARATOR;
		} else {
			$base = $relative_class;
			$relative_dir = '';
		}
		// directory for the namespace
		$bp = __DIR__.DIRECTORY_SEPARATOR.'lib'.DIRECTORY_SEPARATOR.$relative_dir;
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
//	public function IsPluginModule()		{ return FALSE; }
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
		return ''.@file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'include'.DIRECTORY_SEPARATOR.'changelog.inc');
	}

	public function GetDependencies()
	{
		if ($this->before20) {
			return array('CMSMailer'=>'1.0');
		} else {
			return array();
		}
	}

	public function GetHelp()
	{
		//construct frontend-url (so no admin login is needed)
		//cmsms 1.10+ also has ->create_url();
		//deprecated pretty-url
/*		$returnid = cmsms()->GetContentOperations()->GetDefaultContent();
		$oldurl = $this->CreateLink($id,'default',$returnid,'',array(),'',TRUE,FALSE,'',FALSE,'cron/run');
		$url = $this->CreateLink ('_','default',1,'',array(),'',TRUE);
		//strip the fake returnid, so that the default will be used
		$sep = strpos ($url, '&amp;');
		$newurl = substr($url, 0, $sep);
		return $this->Lang ('help_module',$newurl,$oldurl);
*/
		return $this->Lang('help_module');
	}

	public function VisibleToAdminUser()
	{
		return
		 $this->CheckPermission('ModifyAuthProperties') ||
		 $this->CheckPermission('ReviewAuthProperties') ||
		 $this->CheckPermission('SendAuthEvents');
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
		$this->RegisterRoute('/[Cc]ron\/([a-zA-Z0-9_-]+)(\/.*?)?$/',
			array('action' => 'default',
				'showtemplate' => 'FALSE', //NOT FALSE or any of its equivalents
				'returnid' => $rid
			));
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
		return array(
			new Auther\Cleanold_task(),
//			new Auther\Clearcache_task()
		);
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
			$ok = $this->CheckPermission($this->PermAdminName);
			if (!$ok) $ok = $this->CheckPermission($this->PermSeeName);
			if (!$ok) $ok = $this->CheckPermission($this->PermEditName);
			if (!$ok) $ok = $this->CheckPermission($this->PermPerName);
			if (!$ok) $ok = $this->CheckPermission($this->PermAddName);
			if (!$ok) $ok = $this->CheckPermission($this->PermDelName);
			if (!$ok) $ok = $this->CheckPermission($this->PermModName);
			if (!$ok) $ok = $this->CheckPermission($this->PermStructName);
			break;
		//bookings
		 case 'view':
			$name = $this->PermSeeName;
			$ok = $this->CheckPermission($name);
			break;
		 case 'book':
			$name = $this->PermEditName;
			$ok = $this->CheckPermission($name);
			break;
		 case 'admin':
			$name = $this->PermAdminName;
			$ok = $this->CheckPermission($name);
			break;
		//bookers
		 case 'booker':
			$name = $this->PermPerName;
			$ok = $this->CheckPermission($name);
			break;
		//resources
		 case 'add':
			$name = $this->PermAddName;
			$ok = $this->CheckPermission($name);
			break;
		 case 'modify':
			$name = $this->PermModName;
			$ok = $this->CheckPermission($name);
			break;
		 case 'delete':
			$name = $this->PermDelName;
			$ok = $this->CheckPermission($name);
			break;
		//module
		 case 'module':
			$name = $this->PermStructName;
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
	/**
	_PrettyMessage:
	@text: text to display, or if @key = TRUE, a lang-key for the text to display
	@success: optional default TRUE whether to style message as positive
	@key: optional default TRUE whether @text is a lang key or raw
	*/
	public function _PrettyMessage($text, $success=TRUE, $key=TRUE)
	{
		$base = ($key) ? $this->Lang($text) : $text;
		if ($success)
			return $this->ShowMessage($base);
		else {
			$msg = $this->ShowErrors($base);
			//strip the link
			$pos = strpos($msg,'<a href=');
			$part1 = ($pos !== FALSE) ? substr($msg,0,$pos) : '';
			$pos = strpos($msg,'</a>',$pos);
			$part2 = ($pos !== FALSE) ? substr($msg,$pos+4) : $msg;
			$msg = $part1.$part2;
			return $msg;
		}
	}
}
