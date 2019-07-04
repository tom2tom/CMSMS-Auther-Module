<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
# Library file: Cleanold handles system cron event - cleanup ...
#----------------------------------------------------------------------

namespace Auther;

class authCleanoldTask implements \CmsRegularTask
{
	public function get_name()
	{
		return get_class();
	}

	protected function &get_module()
	{
		return \ModuleOperations::get_instance()->get_module_instance('Auther', '', TRUE);
	}

	public function get_description()
	{
		return $this->get_module()->Lang('taskdescription_cleanold');
	}

	public function test($time='')
	{
		$mod = $this->get_module();
//		$sql = 'SELECT 1 AS gone FROM '.$mod->OnceTable.' WHERE active=0 UNION SELECT 1 AS gone FROM '.$mod->RepeatTable.' WHERE active=0';
//		$res = \cmsms()->GetDB()->GetOne($sql);
		$res = TRUE; //TODO
		return ($res != FALSE);
	}

	public function execute($time='')
	{
/*
		$mod = $this->get_module();
		$sql = <<<EOS
SELECT O.bkg_id,I.item_id,I.timezone FROM $mod->OnceTable O
JOIN $mod->ItemTable I ON O.item_id=I.item_id
WHERE O.active=0
EOS;
		$db = \cmsms()->GetDB();
		$rows = $db->GetArray($sql);
		if ($rows) {
			$sql = 'DELETE FROM '.$mod->OnceTable.' WHERE bkg_id=';
			$utils = new Utils();
			foreach ($rows as $one) {
				$st = $utils->GetZoneTime($one['timezone']);
				$base = PHP_INT_MAX - 10000000; //TODO;
				$len = $utils->GetInterval($mod, $one['item_id'], 'keep', 0);
				if (0) { //$st > $base + $len) {
					$db->Execute($sql.$one['bkg_id']);
				}
			}
		}
*/
		//TODO also $mod->RepeatTable
		//TODO also consequent $mod->DispTable records
		return TRUE;
	}

	public function on_success($time='')
	{
	}

	public function on_failure($time='')
	{
	}
}
