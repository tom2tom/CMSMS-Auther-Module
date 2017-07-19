<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
namespace Auther;

class Crypter Extends Encryption
{
	const STRETCHES = 8192;
	protected $mod;

	/*
	constructor:
	@mod: reference to current module object
	@method: optional openssl cipher type to use, default 'BF-CBC'
	@stretches: optional number of extension-rounds to apply, default 8192
	*/
	public function __construct(&$mod, $method='BF-CBC', $stretches=self::STRETCHES)
	{
		$this->mod = $mod;
		parent::__construct($method, 'default', $stretches);
	}

	/**
	encrypt_preference:
	@value: value to be stored, normally a string
	@key: module-preferences key
	*/
	public function encrypt_preference($key, $value)
	{
		$s = \cmsms()->GetConfig()['ssl_url'].$this->mod->GetModulePath(); //site&module-dependent
		$value = parent::encrypt($value,
			hash_hmac('sha1', $this->mod->GetPreference('nQCeESKBr99A').$s, $key));
		$this->mod->SetPreference(hash('sha1', $key.$s), base64_encode($value));
	}

	/**
	decrypt_preference:
	@key: module-preferences key
	Returns: plaintext string, or FALSE
	*/
	public function decrypt_preference($key)
	{
		$s = \cmsms()->GetConfig()['ssl_url'].$this->mod->GetModulePath();
		$value = base64_decode($this->mod->GetPreference(hash('sha1', $key.$s)));
		return parent::decrypt($value,
			hash_hmac('sha1', $this->mod->GetPreference('nQCeESKBr99A').$s, $key));
	}

	/**
	encrypt_value:
	@value: value to encrypted, may be empty string
	@pw: optional password string, default FALSE (meaning use the module-default)
	@based: optional boolean, whether to base64_encode the encrypted value, default FALSE
	@escaped: optional boolean, whether to escape single-quote chars in the (raw) encrypted value, default FALSE
	Returns: encrypted @value, or just @value if it's empty or if password is empty
	*/
	public function encrypt_value($value, $pw=FALSE, $based=FALSE, $escaped=FALSE)
	{
		$value .= '';
		if ($value) {
			if (!$pw) {
				$pw = self::decrypt_preference('masterpass');
			}
			if ($pw) {
				$value = parent::encrypt($value, $pw);
				if ($based) {
					$value = base64_encode($value);
				} elseif ($escaped) {
					$value = str_replace('\'', '\\\'', $value); //facilitate db-field storage
				}
			}
		}
		return $value;
	}

	/**
	decrypt_value:
	@value: string to be decrypted, may be empty
	@pw: optional password string, default FALSE (meaning use the module-default)
	@based: optional boolean, whether @value is base64_encoded, default FALSE
	@escaped: optional boolean, whether single-quote chars in (raw) @value have been escaped, default FALSE
	Returns: decrypted @value, or just @value if it's empty or if password is empty
	*/
	public function decrypt_value($value, $pw=FALSE, $based=FALSE, $escaped=FALSE)
	{
		if ($value) {
			if (!$pw) {
				$pw = self::decrypt_preference('masterpass');
			}
			if ($pw) {
				if ($based) {
					$value = base64_decode($value);
				} elseif ($escaped) {
					$value = str_replace('\\\'', '\'', $value);
				}
				$value = parent::decrypt($value, $pw);
			}
		}
		return $value;
	}

	/**
	hash_value:
	@value: value to be hashed, may be empty string
	@pw: optional password string, default FALSE (meaning use the module-default)
	@raw: optional boolean, whether to return raw binary data, default TRUE
	Returns: hashed @value, or just @value if it's empty or if password is empty
	*/
	public function hash_value($value, $pw=FALSE, $raw=TRUE)
	{
		$value .= '';
		if ($value) {
			if (!$pw) {
				$pw = self::decrypt_preference('masterpass');
			}
			if ($pw) {
				$key = $this->extendKey('sha512', $pw,
					$this->mod->GetPreference('nQCeESKBr99A'), $this->rounds,
					$this->getOpenSSLKeysize() * 2);
				$s = hash_hmac('sha512', $value, $key, $raw);
				if ($raw) {
					return str_replace('\'', '\\\'', $s);
				}
				return $s;
			}
		}
		return $value;
	}
}
