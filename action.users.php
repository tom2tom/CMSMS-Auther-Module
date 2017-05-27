<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$pmod = $this->_CheckAccess('admin') || $this->_CheckAccess('user');
$psee = $this->_CheckAccess('view');
if (!($pmod || $psee)) {
	exit;
}

if (isset($params['close'])) {
	$this->Redirect($id, 'defaultadmin');
}

if (!function_exists('displaywhen')) {
 function displaywhen($dt, $stamp)
 {
	$dt->setTimestamp($stamp);
	return $dt->format('Y-m-d H:i');
 }
}

$cid = (int)$params['ctx_id'];
$utils = new Auther\Utils();

if (isset($params['delete'])) {
	if (!$pmod) {
		exit;
	}
	if (empty($params['sel'])) {
		$utils->DeleteUser($this, $params['usr_id']);
	} else {
		$utils->DeleteUser($this, $params['sel']);
	}
} elseif (isset($params['activate'])) {
	if (!$pmod) {
		exit;
	}
	if (empty($params['sel'])) {
		$utils->ActivateUser($this, $params['usr_id'], $params['to_state']);
	} else {
		$utils->ActivateUser($this, $params['sel']);
	}
} elseif (isset($params['reset'])) {
	if (!$pmod) {
		exit;
	}
	if (empty($params['sel'])) {
		$utils->ResetUser($this, $params['usr_id'], $params['to_state']);
	} else {
		$utils->ResetUser($this, $params['sel']);
	}
} elseif (isset($params['import'])) {
	if (!$pmod) {
		exit;
	}
	$this->Redirect($id, 'import', '', ['resume'=>'users', 'ctx_id'=>$cid]);
}

$tplvars = [
	'mod' => $pmod,
	'see' => $psee
];

$tplvars['pagenav'] = $utils->BuildNav($this,$id,$returnid,$params);
$hidden = ['ctx_id' => $cid]; //TODO etc
$tplvars['startform'] = $this->CreateFormStart($id,'users',$returnid,'POST',
	'','','',$hidden);
//$tplvars['hidden'] = NULL; //TODO
$tplvars['endform'] = $this->CreateFormEnd();

$t = $utils->ContextName($cid);
$tplvars['title'] = $this->Lang('title_usersfor',$t);

if (!empty($msg)) {
	$tplvars['message'] = $msg;
} elseif (!empty($params['message'])) {
	$tplvars['message'] = $params['message'];
}

//$utils = new Auther\Utils();
$baseurl = $this->GetModuleURLPath();

$jsfuncs = []; //script accumulators
$jsloads = [];
$jsincs = [];

$theme = ($this->before20) ? cmsms()->get_variable('admintheme'):
	cms_utils::get_theme_object();

$pre = cms_db_prefix();
$sql = 'SELECT id,publicid,name,address,addwhen,lastuse,privreset,active FROM '.$pre.'module_auth_users WHERE context_id=? ORDER BY publicid';
$data = $db->GetArray($sql, [$cid]);
if ($data) {
	$tplvars['title_name'] = $this->Lang('title_name');
	$tplvars['title_first'] = $this->Lang('title_register');
	$tplvars['title_last'] = $this->Lang('title_lastuse');
	$tplvars['title_addr'] = $this->Lang('title_addressable');
	$tplvars['title_reset'] = $this->Lang('title_pending_reset');
	$tplvars['title_active'] = $this->Lang('title_active');

	$icon_see = $theme->DisplayImage('icons/system/view.gif',$this->Lang('tip_view'),'','','systemicon');
	$icon_yes = $theme->DisplayImage('icons/system/true.gif',$this->Lang('yes'),'','','systemicon');
	$icon_no = $theme->DisplayImage('icons/system/false.gif',$this->Lang('no'),'','','systemicon');
	if ($pmod) {
		$icon_edit = $theme->DisplayImage('icons/system/edit.gif',$this->Lang('tip_edit'),'','','systemicon');
		$icon_delete = $theme->DisplayImage('icons/system/delete.gif',$this->Lang('tip_delete'),'','','systemicon');
	}

	$config = cmsms()->GetConfig();
	$zone = $config['timezone'];
	try {
		$tz = new DateTimeZone($zone);
		$dt = new DateTime('now', $tz);
		$offset = $tz->getOffset($dt);
	} catch (Exception $e) {
		$offset = 0;
	}
	$dt = new DateTime('@0', NULL);

	$cfuncs = new Auther\Crypter($this);

	$rows = [];
	foreach ($data as &$one) {
		$uid = (int)$one['id'];
		$oneset = new stdClass();
		if ($one['name']) {
			$t = $cfuncs->decrypt_value($one['name']);
		} else {
			$t = $one['publicid'];
		}
		if ($pmod) {
			$oneset->name = $this->CreateLink($id, 'openuser', '', $t,
				['ctx_id'=>$cid,'usr_id'=>$uid,'edit'=>1]);
		} else {
			$oneset->name = $t;
		}
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
		if ($pmod) {
			if ($one['privreset']) {
				$icon = $icon_yes;
				$to = 0;
			} else {
				$icon = $icon_no;
				$to = 1;
			}
			$oneset->reset = $this->CreateLink($id,'users','',$icon,
				['ctx_id'=>$cid,'reset'=>1,'usr_id'=>$uid,'to_state'=>$to]);
			if ($one['active']) {
				$icon = $icon_yes;
				$to = 0;
			} else {
				$icon = $icon_no;
				$to = 1;
			}
			$oneset->active = $this->CreateLink($id,'users','',$icon,
				['ctx_id'=>$cid,'activate'=>1,'usr_id'=>$uid,'to_state'=>$to]);
		} else {
			$oneset->reset = ($one['privreset']) ? $icon_yes : $icon_no;
			$oneset->active = ($one['active'] > 0) ? $icon_yes : $icon_no;
		}
		$oneset->see = $this->CreateLink($id,'openuser','',$icon_see,
			['ctx_id'=>$cid,'usr_id'=>$uid,'edit'=>0]);
		if ($pmod) {
			$oneset->edit = $this->CreateLink($id,'openuser','',$icon_edit,
				['ctx_id'=>$cid,'usr_id'=>$uid,'edit'=>1]);
			$oneset->del = $this->CreateLink($id,'users','',$icon_delete,
				['ctx_id'=>$cid,'delete'=>1,'usr_id'=>$uid]);
			$oneset->sel = $this->CreateInputCheckbox($id,'sel[]',$uid,-1);
		}
		$rows[] = $oneset;
	}
	unset($one);

	$tplvars['users'] = $rows;
	$uc = count($rows);
	$tplvars['ucount'] = $uc;

	if ($uc > 1) {
		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/lib/js/jquery.metadata.min.js"></script>
<script type="text/javascript" src="{$baseurl}/lib/js/jquery.SSsort.min.js"></script>
EOS;
		//TODO make page-rows count window-size-responsive
		$pagerows = $this->GetPreference('pagerows', 20); //TODO init this
		if ($pagerows && $uc > $pagerows) {
			$tplvars['hasnav'] = 1;
			//setup for SSsort
			$choices = array(strval($pagerows) => $pagerows);
			$f = ($pagerows < 4) ? 5 : 2;
			$n = $pagerows * $f;
			if ($n < $rc)
				$choices[strval($n)] = $n;
			$n *= 2;
			if ($n < $rc)
				$choices[strval($n)] = $n;
			$choices[$this->Lang('all')] = 0;
			$tplvars['rowchanger'] =
				$this->CreateInputDropdown($id, 'pagerows', $choices, -1, $pagerows,
				'onchange="pagerows(this);"').'&nbsp;&nbsp;'.$this->Lang('pagerows');
			$curpg = '<span id="cpage">1</span>';
			$totpg = '<span id="tpage">'.ceil($rc/$pagerows).'</span>';
			$tplvars += [
				'first' => '<a href="javascript:pagefirst()">'.$this->Lang('first').'</a>',
				'prev' => '<a href="javascript:pageback()">'.$this->Lang('previous').'</a>',
				'next' => '<a href="javascript:pageforw()">'.$this->Lang('next').'</a>',
				'last' => '<a href="javascript:pagelast()">'.$this->Lang('last').'</a>',
				'pageof' => $this->Lang('pageof', $curpg, $totpg)
			];

			$jsfuncs[] = <<<'EOS'
var pagedtable;

function pagefirst() {
 $.SSsort.movePage(pagedtable,false,true);
}
function pagelast() {
 $.SSsort.movePage(pagedtable,true,true);
}
function pageforw() {
 $.SSsort.movePage(pagedtable,true,false);
}
function pageback() {
 $.SSsort.movePage(pagedtable,false,false);
}
function pagerows(cb) {
 $.SSsort.setCurrent(pagedtable,'pagesize',parseInt(cb.value));
}
EOS;
			$jsloads[] = <<<'EOS'
 pagedtable = document.getElementById('userstable');
EOS;
			$xjs = ",
  paginate: true,
  pagesize: $pagerows,
  currentid: 'cpage',
  countid: 'tpage'
";
		} else { //no rows-paging
			$xjs = '';
		}

		$jsloads[] = <<<EOS
 $.SSsort.addParser({
  id: 'icon',
  is: function(s,node) {
   var \$i = $(node).find('img');
   return \$i.length > 0;
  },
  format: function(s,node) {
   var \$i = $(node).find('img');
   return \$i[0].src;
  },
  watch: false,
  type: 'text'
 });
 $('#userstable').SSsort({
  sortClass: 'SortAble',
  ascClass: 'SortUp',
  descClass: 'SortDown',
  oddClass: 'row1',
  evenClass: 'row2',
  oddsortClass: 'row1s',
  evensortClass: 'row2s'{$xjs}
 });
EOS;
	}

	if ($pmod) {
		if ($uc > 1) {
			$tplvars['header_checkbox'] =
				$this->CreateInputCheckbox($id,'selectall',TRUE,FALSE,'onclick="select_all(this);"');

			$jsfuncs[] = <<<EOS
function select_all(cb) {
 $('#userstable > tbody').find('input[type="checkbox"]').attr('checked',cb.checked);
}
EOS;
			$jsloads[] = <<<EOS
 var shifted = false,
  firstClicked = null,
  \$checks;
 $(document).keydown(function(e) {
  if (e.keyCode == 16) {
   shifted = true;
  }
 }).keyup(function(e) {
  if (e.keyCode == 16) {
   shifted = false;
  }
 });
 \$checks = $('#userstable > tbody').find('input[type="checkbox"]');
 \$checks.click(function() {
  if (shifted && firstClicked) {
   var i,
    first = \$checks.index(firstClicked),
    last = \$checks.index(this),
    chk = firstClicked.checked;
   if (first < last) {
    for (i = first; i <= last; i++) {
     \$checks[i].checked = chk;
    }
   } else if (first > last) {
    for (i = first; i >= last; i--) {
     \$checks[i].checked = chk;
    }
   }
  }
  firstClicked = this;
 });
EOS;
		}
		$tplvars['delete'] = $this->CreateInputSubmit($id,'delete',$this->Lang('delete'),
			'title="'.$this->Lang('tip_deluser').'"');

		$jsincs[] = <<<EOS
<script type="text/javascript" src="{$baseurl}/lib/js/jquery.alertable.min.js"></script>
EOS;

		$jsfuncs[] = <<<EOS
function any_selected() {
 var cb = $('#userstable input[name="{$id}sel[]"]:checked');
 return (cb.length > 0);
}
EOS;
		$t = $this->Lang('confirm_delsel2');
		$jsloads[] = <<<EOS
 $('#itemacts #{$id}delete').click(function() {
  if (any_selected()) {
   var tg = this;
   $.alertable.confirm('$t', {
    okName: '{$this->Lang('proceed')}',
    cancelName: '{$this->Lang('cancel')}'
   }).then(function() {
    $(tg).trigger('click.deferred');
   });
  }
  return false;
 });
EOS;
		$t = $this->Lang('confirm_del','%s');
		$jsloads[] = <<<EOS
 $('#userstable .linkdel > a').click(function(ev) {
  var tg = ev.target,
    nm = $(this.parentNode).siblings(':first').children(':first').text(),
   msg = '$t'.replace('%s',nm);
  $.alertable.confirm(msg, {
   okName: '{$this->Lang('proceed')}',
   cancelName: '{$this->Lang('cancel')}'
  }).then(function() {
   $(tg).trigger('click.deferred');
  });
  return false;
 });
EOS;
		$tplvars['reset'] = $this->CreateInputSubmit($id,'reset',$this->Lang('reset'),
			'title="'.$this->Lang('tip_resetuser').'"');
		$tplvars['activate'] = $this->CreateInputSubmit($id,'activate',$this->Lang('activate'),
			'title="'.$this->Lang('tip_activeuser').'"');

		$t = $this->Lang('confirm');
		$jsloads[] = <<<EOS
 $('#itemacts #{$id}reset,#itemacts #{$id}activate').click(function() {
  if (any_selected()) {
   var tg = this;
   $.alertable.confirm('$t', {
    okName: '{$this->Lang('proceed')}',
    cancelName: '{$this->Lang('cancel')}'
   }).then(function() {
    $(tg).trigger('click.deferred');
   });
  }
  return false;
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
		['ctx_id'=>$cid,'usr_id'=>-1,'edit'=>1]);
	$tplvars['textlinkadd'] = $this->CreateLink($id,'openuser','',$t,
		['ctx_id'=>$cid,'usr_id'=>-1,'edit'=>1]);
	$tplvars['import'] = $this->CreateInputSubmit($id,'import',$this->Lang('import'),
		'title="'.$this->Lang('tip_importuser').'"');
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
