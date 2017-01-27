<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
namespace Auther;

class Crypter
{
	const STRETCHES = 12; //hence 2**12

	/**
	encrypt_preference:
	@mod: reference to current Auther module object
	@value: value to be stored, normally a string
	@key: module-preferences key
	*/
	public function encrypt_preference(&$mod, $key, $value)
	{
		$config = \cmsms()->GetConfig();
		$root = (empty($_SERVER['HTTPS'])) ? $config['root_url'] : $config['ssl_url'];
		$hash = hash('crc32b', $root.$mod->GetModulePath()); //site-dependent
		$e = new Encryption('BF-CBC', self::STRETCHES);
		$st = $e->encrypt($value, $hash);
		$mod->SetPreference($key, base64_encode($st));
	}

	/**
	decrypt_preference:
	@mod: reference to current Auther module object
	@key: module-preferences key
	Returns: plaintext string
	*/
	public function decrypt_preference(&$mod, $key)
	{
		$st = base64_decode($mod->GetPreference($key));
		$config = \cmsms()->GetConfig();
		$root = (empty($_SERVER['HTTPS'])) ? $config['root_url'] : $config['ssl_url'];
		$hash = hash('crc32b', $root.$mod->GetModulePath()); //site-dependent
		$e = new Encryption('BF-CBC', self::STRETCHES);
		return $e->decrypt($st, $hash);
	}

	/**
	encrypt_value:
	@mod: reference to current Auther module object
	@value: value to be processed
	@passwd: optional plaintext password, default FALSE
	*/
	public function encrypt_value(&$mod, $value, $passwd=FALSE)
	{
		if ($value) {
			if (!$passwd) {
				$passwd = $this->decrypt_preference($mod, 'masterpass');
			}
			if ($passwd) {
				$e = new Encryption('BF-CBC', self::STRETCHES);
				$value = $e->encrypt($value, $passwd);
			}
		}
		return $value;
	}

	/**
	decrypt_value:
	@mod: reference to current Auther module object
	@value: value to be processed
	@passwd: optional plaintext password, default FALSE
	Returns: plaintext string
	*/
	public function decrypt_value(&$mod, $value, $passwd=FALSE)
	{
		if ($value) {
			if (!$passwd) {
				$passwd = $this->decrypt_preference($mod, 'masterpass');
			}
			if ($passwd) {
				$e = new Encryption('BF-CBC', self::STRETCHES);
				$value = $e->decrypt($value, $passwd);
			}
		}
		return $value;
	}

	public function fusc($str)
	{
		if ($str) {
			$s = substr(base64_encode(md5(microtime())), 0, 5);
			return $s.base64_encode($s.$str);
		}
		return '';
	}

	public function unfusc($str)
	{
		if ($str) {
			$s = base64_decode(substr($str, 5));
			return substr($s, 5);
		}
		return '';
	}
}
