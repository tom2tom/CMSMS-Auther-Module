<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

if (!($this->_CheckAccess('admin') || $this->_CheckAccess('user'))) {
	exit;
}

$uid = (int)$params['item_id'];

//TODO delete user

$this->Redirect($id, 'users', '', []); //TODO parms
