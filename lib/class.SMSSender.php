<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Derived originally from PHPAuth <https://www.phpclasses.org/package/9887-PHP-Register-and-publicid-users-stored-in-a-database.html>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
# Adapted from Notifier module SMSSender class
# Requires PHP 5.4+
#----------------------------------------------------------------------
namespace Auther;

class SMSSender
{
	protected $gateway;
	protected $utils; //SMSG\Utils
	protected $notifutils; //Notifier\Utils TODO
	protected $fromnum; //whether gateway supports a specific sender-number
	protected $addprefix; //whether gateway requires country-prefix for each phone no. or else supports phone no. as-is
	protected $addplus; //whether gateway requires a leading '+' in the country-prefix, if any

	public function __construct()
	{
		$this->notifutils = FALSE;
		$this->utils = new \SMSG\Utils();
		$this->gateway = $this->utils->get_gateway();
		if ($this->gateway) {
			$this->addplus = FALSE;
			if (method_exists($this->gateway, 'support_custom_sender')) {
				$this->fromnum = $this->gateway->support_custom_sender();
			} else {
				$this->fromnum = FALSE;
			}
			if (method_exists($this->gateway, 'require_country_prefix')) {
				$this->addprefix = $this->gateway->require_country_prefix();
				if ($this->addprefix && method_exists($this->gateway, 'require_plus_prefix')) {
					$this->addplus = $this->gateway->require_plus_prefix();
				}
			} else {
				$this->addprefix = TRUE;
			}
		}
	}

	/*
	 $number is string with no whitespace, $prefix is string [+]digit(s) and maybe whitespace, or FALSE
	*/
	private function AdjustPhone($number, $prefix)
	{
		if (!$this->addprefix) {
			if (!$this->addplus && $number[0] == '+') {
				$number = substr($number, 1);
			} //assume it's already a full number i.e. +countrylocal
			return $number;
		}
		if ($prefix) {
			$p = str_replace(' ', '', $prefix);
			if ($p[0] == '+') {
				$p = substr($p, 1);
			}
		} else {
			$p = '';
		}

		$l = strlen($p);
		if ($l > 0) {
			if (substr($number, 0, $l) != $p) {
				if ($number[0] === '0') {
					$number = $p.substr($number, 1);
				}
			}
		}
		if ($this->addplus && $number[0] != '+') {
			$number = '+'.$number;
		} elseif (!$this->addplus && $number[0] == '+') {
			$number = substr($number, 1);
		}
		return $number;
	}

	/**
	Sends SMS(s)
	@mod: reference to current module object
	@prefix: string, [+]digit(s), or TODO some code, or FALSE
	@to: validated phone no. or array of them
	@from: validated phone no. to be used (if the gateway allows) as sender, or FALSE
	@body: the message
	Returns: 2-member array,
	 [0] FALSE if no addressee or no SMSG-module gateway, otherwise boolean cumulative result of gateway->send()
	 [1] '' or error message e.g. from gateway->send() to $to
	*/
	public function Send(&$mod, $prefix, $to, $from, $body)
	{
		if (!$this->gateway) {
			return [FALSE, $mod->Lang('err_system')];
		}
		if (!$to) {
			return [FALSE, ''];
		} elseif (!is_array($to)) {
			$to = array($to);
		}
		if (!$body || !$this->utils->text_is_valid($body)) {
			return [FALSE, $mod->Lang('err_text').' \''.$body.'\''];
		}
		if ($prefix && !is_numeric($prefix)) {
			if (!$this->notifutils) {
				$this->notifutils = new \Notifier\Utils(); //TODO
			}
			$prefix = (string)$this->notifutils->phoneprefix(trim($prefix));
		}
		if ($from && $this->fromnum) {
			$from = self::AdjustPhone($from, $prefix);
			$this->gateway->set_from($from);
		}
		$this->gateway->set_msg($body);
		$err = '';
		//assume gateway doesn't support batching
		foreach ($to as $num) {
			$num = self::AdjustPhone($num, $prefix);
			$this->gateway->set_num($num);
			if (!$this->gateway->send()) {
				if ($err) {
					$err .= '<br />';
				}
				$err .= $num.': '.$this->gateway->get_statusmsg();
			}
		}
		return [($err==''), $err];
	}
}
