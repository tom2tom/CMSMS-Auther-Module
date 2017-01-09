<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$tplvars = array(
//	'see' => $psee,
	'add' => $padd,
	'del' => $pdel,
	'mod' => $mod,
);

$baseurl = $this->GetModuleURLPath();
$jsfuncs = array(); //script accumulators
$jsloads = array();
$jsincs = array();

$jsall = NULL;
$utils->MergeJS($jsincs, $jsfuncs, $jsloads, $jsall);
unset($jsincs);
unset($jsfuncs);
unset($jsloads);

echo Auther\Utils::ProcessTemplate($this, 'validate.tpl', $tplvars);
//inject constructed js after other content (pity we can't get to </body> or </html> from here)
if ($jsall) {
	echo $jsall;
}
