<?php
/*
  A simple CAPTCHA'ish class
  Derived in part from original (C) 2011 by Cory LaViska
*/
namespace Auther\Captcha;

class SimpleCaptcha
{
	/**
	generate:
	Constructs text string, and an image file showing that text in specified directory
	@params: array with members:
	'code' = optional captcha text to be displayed
	'background' = absolute filepath .ttf font file
	'font' = absolute filepath .png image file
	'size' = displed font-size in points
	'color' = displayed text color 3- or 6-byte hexadecimal string, leading '#' optional
	'length' = captcha text byte-size
	'path' = absolute filepath for cacheing image file
	Returns: text string of specified length
	*/
	public function generate($params)
	{
		// Check for GD library
		if (!function_exists('gd_info')) {
			throw new \Exception('Required GD library is missing');
		}

		// Generate CAPTCHA code if not set by upstream
		if (empty($params['code'])) {
			$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghjkmnpqrstuvwxyz';
			$cl = strlen($chars) - 1;
			$len = $params['length'];
			$code = str_repeat('0', $len);
			for ($i = 0; $i < $len; $i++) {
				$code[$i] = $chars[mt_rand(0, $cl)];
			}
			$params['code'] = $code;

		} else {
			$code = $params['code'];
		}

		// Generate image
		$file = $this->draw_image($params);

		return ['code'=>$code, 'file'=>$file];
	}

	public function clean($image_path)
	{
		if (is_file($image_path)) {
			@unlink($image_path);
		}
	}

	protected function is_absolute($filepath)
	{
		if (!$filepath) {
			return FALSE;
		}
		// root / (*NIX) or \ (Windows)
		if ($filepath[0] == '/' || $filepath[0] == '\\') {
			return TRUE;
		}
		// Windows root
		$l = strlen($filepath);
		if ($l > 1 && $filepath[1] == ':' && ctype_alpha($filepath[0])) {
			if ($l == 2) {
				return TRUE;
			}
			// Normal case: "C:/ or "C:\"
			if ($filepath[2] == '/' || $filepath[2] == '\\') {
				return TRUE;
			}
		}
		return FALSE;
	}

	/*
	$hex_str: 3- or 6-byte hexadecimal string, leading '#' optional
	$as_string:
	$separator:
	Returns: array or string
	*/
	protected function hex2rgb($hex_str, $as_string = FALSE, $separator = ',')
	{
		$hex_str = preg_replace("/[^0-9A-Fa-f]/", '', $hex_str); // Ensure a proper hex string
		$rgb_array = [];
		if (strlen($hex_str) == 6 ) {
			$color_val = hexdec($hex_str);
			$rgb_array['r'] = 0xFF & ($color_val >> 0x10);
			$rgb_array['g'] = 0xFF & ($color_val >> 0x8);
			$rgb_array['b'] = 0xFF & $color_val;
		} elseif (strlen($hex_str) == 3 ) {
			$rgb_array['r'] = hexdec(str_repeat(substr($hex_str, 0, 1), 2));
			$rgb_array['g'] = hexdec(str_repeat(substr($hex_str, 1, 1), 2));
			$rgb_array['b'] = hexdec(str_repeat(substr($hex_str, 2, 1), 2));
		} else {
			return FALSE;
		}
		return ($as_string) ? implode($separator, $rgb_array) : $rgb_array;
	}

	protected function hash($str)
	{
		//djb2a hash : see http://www.cse.yorku.ca/~oz/hash.html
		$l = strlen($str);
		$num = 5381;
		for ($i = 0; $i < $l; $i++) {
			$num = ($num + ($num << 5)) ^ $str[$i]; //$num = $num*33 ^ $str[$i]
		}
		return $num;
	}

	/*
	Returns: basename of cached .png file
	*/
	protected function draw_image($params)
	{
		$background = $params['background'];
		if (!$this->is_absolute($background)) {
			$background = __DIR__.DIRECTORY_SEPARATOR.$background;
		} else {
			$background = realpath($background);
		}
		if (!file_exists($background)) {
			throw new \Exception('Image-background file not found: '.$params['background']);
		}

		$font = $params['font'];
		if (!$this->is_absolute($font)) {
			$font = __DIR__.DIRECTORY_SEPARATOR.$font;
		} else {
			$font = realpath($font);
		}
		if (!file_exists($font)) {
			throw new \Exception('Image-font file not found: '.$params['font']);
		}

		$tmpdir = $params['path'];
		if (!is_dir($tmpdir) || !is_writable($tmpdir)) {
			throw new \Exception('Image-store directory not available: '.$tmpdir);
		}

		$font_size = $params['size'];
		$v = gd_info()['GD Version'];
		if (strpos($v,'2.') === FALSE) {
			$font_size = floor($font_size * 72);
		}

		$text = $params['code'];
		$text_box_size = imagettfbbox($font_size, 0.0, $font, $text);
		$box_width = abs($text_box_size[6] - $text_box_size[2]);
		$box_height = abs($text_box_size[5] - $text_box_size[1]);

		list($bg_width, $bg_height, $bg_type, $bg_attr) = getimagesize($background);

		$img = imagecreatefrompng($background);
		//stretch background if needed PHP 5.5+
		if ($bg_width < $box_width + 10 || $bg_height < $box_height + 10) {
			if (function_exists('imagescale')) {
				$bg_width = $box_width + 10;
				$bg_height = $box_height + 10;
				$img = imagescale($img, $bg_width, $bg_height);
			}
		}

		$color = $this->hex2rgb($params['color']);
		$color = imagecolorallocate($img, $color['r'], $color['g'], $color['b']);

		// Determine text position
		$text_pos_x = ($bg_width - $box_width) / 2;

		$text_pos_y_min = $box_height;
		$text_pos_y_max = ($bg_height) - ($box_height / 2);
		if ($text_pos_y_min > $text_pos_y_max) {
			$temp_text_pos_y = $text_pos_y_min;
			$text_pos_y_min = $text_pos_y_max;
			$text_pos_y_max = $temp_text_pos_y;
		}
		$text_pos_y = ($text_pos_y_min + $text_pos_y_max) / 2;

		// Draw text
		imagettftext($img, $font_size, 0.0, $text_pos_x, $text_pos_y, $color, $font, $text);
		$pref = $this->hash($text);
		$fn = uniqid($pref).'.png';
		$fp = $tmpdir.DIRECTORY_SEPARATOR.$fn;

		imagepng($img, $fp, 6);
		return $fn;
	}
}
