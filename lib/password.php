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
	if ($passwd == FALSE && !is_numeric($passwd)) {
		trigger_error('No password provided', E_USER_WARNING);
		return '';
	} elseif (!function_exists('crypt')) {
		trigger_error('Crypt extension must be present for password hashing', E_USER_WARNING);
		return FALSE;
	}
	//obfuscate short passwords (other than time-wasting, useless, really)
	$t = 1;
	while (($len = bytelen($passwd)) < 32) {
		$passwd .= str_shuffle($passwd);
		$t += $t;
	}
	$passwd .= chr($t);

	$e = new Encryption(\MCRYPT_TWOFISH, \MCRYPT_MODE_CBC, 10000);
	return $e->encrypt($passwd, $masterkey);
}

/**
password_verify:
Verify @password against @hash

@passwd: string The password to verify
@hash: string The hash to verify against
@masterkey: string Persistent key for password en/decoding
@tries: no. of verification attempts

Returns: boolean Whether @passwd matches @hash
*/
function password_verify($passwd, $hash, $masterkey, $tries=1)
{
	if (!function_exists('crypt')) {
		trigger_error('Crypt extension must be present for password verification', E_USER_WARNING);
		sleep(1);
		return FALSE;
	}
	if (password_hash($passwd, $masterkey) === $hash) {
		return TRUE;
	}
	$t = min(2000, $tries * 500);
	usleep($t * 1000);
	return FALSE;
}

/**
password_retrieve:
Unhash @hash

@hash: string a hashed password
@masterkey: string Persistent key for password en/decoding

Returns: plaintext string, or FALSE
*/
function password_retrieve($hash, $masterkey)
{
	if (!function_exists('crypt')) {
		trigger_error('Crypt extension must be present for password retrieval', E_USER_WARNING);
		return FALSE;
	}

	$e = new Encryption(\MCRYPT_TWOFISH, \MCRYPT_MODE_CBC, 10000);
	$plain = $e->decrypt($hash, $masterkey);
	if ($plain) {
		$len = bytelen($plain) - 1;
		$t = ord(substr($plain, -1));
		if ($t > 1) {
			$len /= $t;
		}
		return substr($plain, 0, $len);
	}
	return FALSE;
}

/**
bytelen:
Count the number of bytes in @binary_string

Vanilla strlen() might be shadowed by the mbstring extension,
in which case strlen() will count the number of characters
per the internal encoding, which count may be < the wanted number.

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
