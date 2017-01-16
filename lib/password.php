<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------
namespace Auther;

/**
password_hash:
Hash @password

@passwd: string The password to hash
@masterkey: string Persistent key for password en/decoding

Returns: (192 + 16*N)bytes|FALSE The hashed password, or empty string, or FALSE on error.
*/
function password_hash($passwd, $masterkey)
{
	if (!$passwd) {
		trigger_error('No password provided', E_USER_WARNING);
		return '';
	}
	if (!function_exists('crypt')) {
		trigger_error('Crypt extension must be present for password hashing', E_USER_WARNING);
		return FALSE;
	}

	$e = new Encryption(\MCRYPT_TWOFISH, \MCRYPT_MODE_CBC, 10000);
	return $e->encrypt($passwd, $masterkey);
}

/**
password_verify:
Verify @password against @hash

@password: string The password to verify
@hash: string The hash to verify against
@masterkey: string Persistent key for password en/decoding

Returns: boolean Whether @password matches @hash
*/
function password_verify($passwd, $hash, $masterkey)
{
	if (!function_exists('crypt')) {
		trigger_error('Crypt extension must be present for password verification', E_USER_WARNING);
		return FALSE;
	}

	$test = password_hash($passwd, $masterkey);
	if (!$test || bytelen($test) != bytelen($hash)) {
		return FALSE;
	}
	//slower comparison helps resist attacks
	$status = 0;
	for ($i = 0; $i < bytelen($test); $i++) {
		$status |= ($test[$i] ^ $hash[$i]);
	}
	return ($status === 0);
}

/**
password_retrieve:
Unhash @hash

@hash: string a hashed password
@masterkey: string Persistent key for password en/decoding

Returns: plaintext string
*/
function password_retrieve($hash, $masterkey)
{
	if (!function_exists('crypt')) {
		trigger_error('Crypt extension must be present for password retrieval', E_USER_WARNING);
		return FALSE;
	}

	$e = new Encryption(\MCRYPT_TWOFISH, \MCRYPT_MODE_CBC, 10000);
	return $e->decrypt($hash, $masterkey);
}

/**
bytelen:
Count the number of bytes in a binary string

Vanilla strlen() might be shadowed by the mbstring extension.
In that case, strlen() will count the number of *characters*
per the internal encoding, and that may be < the wanted number.

@binary_string: string The input string

Returns: int The number of bytes
*/
function bytelen($binary_string)
{
	if (function_exists('mb_strlen')) {
		return mb_strlen($binary_string, '8bit');
	}
	return strlen($binary_string);
}
