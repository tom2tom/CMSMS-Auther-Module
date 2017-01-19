<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$pmod = $this->_CheckAccess('admin') || $this->_CheckAccess('user');
$psee = $this->_CheckAccess('view');

$cid = $params['item_id'];

if (!function_exists('displaywhen')) {
 function displaywhen($dt, $stamp)
 {
	$dt->setTimestamp($stamp);
	return $dt->format('Y-m-d H:i');
 }
}

if (isset($params['delete'])) {
	if (!$pmod) exit;
	if (!empty($params['sel'])) {
		$utils = new Auther\Utils();
		$utils->DeleteUser($params['sel']);
	}
} elseif (isset($params['import'])) {
	if (!$pmod) exit;
	$utils = new Auther\Utils();
	if (isset($_FILES) && isset($_FILES[$id.'csvfile'])) {
		$funcs = new Auther\Import();
		$res = $funcs->ImportUsers($this, $id);
		$msg = $utils->PrettyMessage($this, $res[1], $res[0], FALSE);
	} else {
		$tplvars = [];
		$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
		$hidden = ['item_id'=>$cid]; //TODO etc
		$tplvars['startform'] = $this->CreateFormStart($id,'users',$returnid,'POST','multipart/form-data','','',
			$hidden);
		$tplvars['endform'] = $this->CreateFormEnd();
		$tplvars['title'] = $this->Lang('title_import');
		$tplvars['chooser'] = $this->CreateInputFile($id,'csvfile','text/csv',25);
		$tplvars['apply'] = $this->CreateInputSubmit($id,'import',$this->Lang('upload'));
		$tplvars['cancel'] = $this->CreateInputSubmit($id,'cancel',$this->Lang('cancel'));
		$tplvars['help'] = $this->Lang('help_import');

		echo $utils->ProcessTemplate($this, 'chooser.tpl', $tplvars);
		return;
	}
} elseif (!($pmod || $psee)) {
	exit;
}

$tplvars = [
	'mod' => $pmod,
	'see' => $psee
];

if (!isset($utils)) {
	$utils = new Auther\Utils();
}

$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = ['item_id' => $cid]; //TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'users',$returnid,'POST','multipart/form-data',
	'','',$hidden);
//$tplvars['hidden'] = NULL; //TODO
$tplvars['endform'] = $this->CreateFormEnd();

$t = $utils->ContextName($cid);
$tplvars['title'] = $this->Lang('title_usersfor',$t);

if (!empty($msg)) {
	$tplvars['message'] = $msg;
}

//$utils = new Auther\Utils();
$baseurl = $this->GetModuleURLPath();

$jsfuncs = []; //script accumulators
$jsloads = [];
$jsincs = [];

$theme = ($this->before20) ? cmsms()->get_variable('admintheme'):
	cms_utils::get_theme_object();

$pre = cms_db_prefix();
$sql = "SELECT id,publicid,address,addwhen,lastuse,active FROM {$pre}module_auth_users WHERE context=? ORDER BY publicid";
$data = $db->GetArray($sql, [$cid]);
if ($data) {
	//TODO support sorting, ?paging
	$tplvars['title_name'] = $this->Lang('title_name');
	$tplvars['title_first'] = $this->Lang('title_register');
	$tplvars['title_last'] = $this->Lang('title_lastuse');
	$tplvars['title_addr'] = $this->Lang('title_addressable');
	$tplvars['title_active'] = $this->Lang('title_active');

	$icon_see = $theme->DisplayImage('icons/system/view.gif',$this->Lang('tip_view'),'','','systemicon');
	$icon_yes = $theme->DisplayImage('icons/system/yes.gif','','','','systemicon');
	$icon_no = $theme->DisplayImage('icons/system/no.gif','','','','systemicon');
	if ($pmod) {
		$icon_edit = $theme->DisplayImage('icons/system/edit.gif',$this->Lang('tip_edit'),'','','systemicon');
		$icon_delete = $theme->DisplayImage('icons/system/delete.gif',$this->Lang('tip_delete'),'','','systemicon');
	}

	$config = cmsms()->GetConfig();
	$zone = $config['timezone'];
	try {
		$tz = new DateTimeZone($zone);
		$offset = $tz->getOffset();
	} catch (Exception $e) {
		$offset = 0;
	}
	$dt = new DateTime('@0', NULL);

	$rows = [];
	foreach ($data as &$one) {
		$uid = (int)$one['id'];
		$oneset = new stdClass();
		$oneset->name = $one['publicid'];
		if ($one['addwhen']) {
			$oneset->reg = displaywhen($dt, $one['addwhen'] + $offset);
		} else {
			$oneset->reg = '--';
		}
		if ($one['lastuse']) {
			$oneset->last = displaywhen($dt, $one['lastuse'] + $offset);
		} else {
			$oneset->last = $this->Lang('none');
		}
		$oneset->addr = ($one['address']) ? $icon_yes : $icon_no;
		$oneset->active = ($one['active'] > 0) ? $icon_yes : $icon_no;
		$oneset->see = $this->CreateLink($id,'openuser','',$icon_see,
			['item_id'=>$uid, 'edit'=>0]);
		if ($pmod) {
			$oneset->edit = $this->CreateLink($id,'openuser','',$icon_edit,
				['item_id'=>$uid,'edit'=>1]);
			$oneset->del = $this->CreateLink($id,'deleteuser','',$icon_delete,
				['item_id'=>$uid]);
			$oneset->sel = $this->CreateInputCheckbox($id,'sel[]',$uid,-1);
		}
		$rows[] = $oneset;
	}
	unset($one);

	$tplvars['users'] = $rows;
	$tplvars['ucount'] = count($rows);

	if ($pmod) {
		$tplvars['delete'] = $this->CreateInputSubmit($id,'delete',$this->Lang('delete'),
			'title="'.$this->Lang('tip_deluser').'"');

		$jsfuncs[] = <<<EOS
function any_selected() {
 var cb = $('#userstable input[name="{$id}sel[]"]:checked');
 return (cb.length > 0);
}
EOS;
		$t = $this->Lang('confirm_delsel'); //TODO
		$jsloads[] = <<<EOS
 $('#itemacts #{$id}delete').click(function() {
  if (any_selected()) {
   return confirm('$t');
  } else {
   return false;
  }
 });
EOS;
		$t = $this->Lang('confirm_del','%s'); //TODO
		$jsloads[] = <<<EOS
 $('#userstable .linkdel > a').click(function() {
  var nm = $(this.parentNode).siblings(':first').children(':first').text();
  return confirm('$t'.replace('%s',nm));
 });
EOS;
	} //$pmod
} else { //no data
	$t = $utils->ContextName($cid);
	$tplvars['nousers'] = $this->Lang('nouser', $t);
	$tplvars['ucount'] = 0;
}

if ($pmod) {
	$t = $this->Lang('adduser');
	$icon_add = $theme->DisplayImage('icons/system/newobject.gif',$t,'','','systemicon');
	$tplvars['iconlinkadd'] = $this->CreateLink($id,'openuser','',$icon_add,
		[]);
	$tplvars['textlinkadd'] = $this->CreateLink($id,'openuser','',$t,
		[]);
	$tplvars['import'] = $this->CreateInputSubmit($id,'import',$this->Lang('import'));
}
$tplvars['close'] = $this->CreateInputSubmit($id,'close',$this->Lang('close'));

$jsall = $utils->MergeJS($jsincs, $jsfuncs, $jsloads);
unset($jsincs);
unset($jsfuncs);
unset($jsloads);

echo $utils->ProcessTemplate($this, 'users.tpl', $tplvars);
if ($jsall) {
	echo $jsall; //inject constructed js after other content
}
