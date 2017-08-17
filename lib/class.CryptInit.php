<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
namespace Auther;

class CryptInit Extends Crypter
{
	/**
	constructor:
	@mod: reference to current module object
	@method: optional openssl cipher type to use, default 'BF-CBC'
	@stretches: optional number of extension-rounds to apply, default 8192
	*/
	public function __construct(&$mod, $method='BF-CBC', $stretches=parent::STRETCHES)
	{
		parent::__construct($mod, $method, 'default', $stretches);
	}

	/**
	clear_preference:
	NB key parent::SKEY should be last-cleared
	@key: module-preferences key
	@s: optional 'localisation' string, default ''
	*/
	public function clear_preference($key, $s='')
	{
		if (!$s) {
			$s = parent::localise();
		}
		$this->mod->RemovePreference(hash('tiger192,3', $s.$key));
	}

	/*
	localise:
	Get constant site/host-specific string.
	All hashes and crypted preferences depend on this
	*/
	protected function localise()
	{
		return cmsms()->GetConfig()['ssl_url'].$this->mod->GetModulePath();
	}

	/**
	init_crypt:
	Must be called ONCE (during installation and/or after any localisation change)
	before any hash or preference-crypt
	@s: optional 'localisation' string, default ''
	*/
	public function init_crypt($s='')
	{
		if (!$s) {
			$s = self::localise().parent::SKEY;
		}
		$value = str_shuffle(openssl_random_pseudo_bytes(9).microtime(TRUE));
		$value = $this->encrypt($value,
			hash_hmac('sha256', $s, parent::SKEY));
		$this->mod->SetPreference(hash('tiger192,3', $s),
			base64_encode($value));
	}

	/**
	encrypt_preference:
	@value: value to be stored, normally a string
	@key: module-preferences key
	@s: optional 'localisation' string, default ''
	*/
	public function encrypt_preference($key, $value, $s='')
	{
		if (!$s) {
			$s = self::localise();
		}
		$value = $this->encrypt(''.$value,
			hash_hmac('sha256', $s.$this->decrypt_preference(parent::SKEY), $key));
		$this->mod->SetPreference(hash('tiger192,3', $s.$key),
			base64_encode($value));
	}
}
