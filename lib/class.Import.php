<?php
#----------------------------------------------------------------------
# Module: Booker - a resource booking module
# Library file: Import - functions for import of module data
#----------------------------------------------------------------------
# See file Booker.module.php for full details of copyright, licence, etc.
#----------------------------------------------------------------------
namespace Auther;

class Import
{
	const DEFAULTPASS = 'change#2468#ASAP'; //this exceeds complexity 3, but not 4

	private function ToChr($match)
	{
		$st = ($match[0][0] == '&') ? 2 : 1;
		return chr(substr($match[0], $st, 2));
	}

	/*
	GetSplitLine:
	Gets line from csv file, splits it into array, reinstates all 'commas' in field values
	@fh: connection/handle for file being processed
	Returns: array or FALSE
	*/
	private function GetSplitLine(&$fh)
	{
		do {
			$fields = fgetcsv($fh, 4096);
			if (is_null($fields) || $fields == FALSE) {
				return FALSE;
			}
		} while (!isset($fields[1]) && is_null($fields[0])); //blank line
		$some = FALSE;
		//convert any separator supported by exporter
		foreach ($fields as &$one) {
			if ($one) {
				$some = TRUE;
				$one = trim(preg_replace_callback(
					['/&#\d\d;/', '/%\d\d%/'], [$this, 'ToChr'], $one));
			}
		}
		unset($one);
		if ($some) {
			return $fields;
		}
		return FALSE; //ignore lines with all fields empty
	}

	/*
	MakeContext:
	Add a row to the contexts table, using default values
	No check here for alias-duplication
	@mod: reference to current Auther module object
	$context: context identifier number or string
	@db: reference to database connection
	@pref: string database tables prefix
	Returns: int identifier of created context
	*/
	private function MakeContext(&$mod, $context, &$db, $pref)
	{
		$cid = $db->GenID($pref.'module_auth_contexts_seq');
		if (is_numeric($context)) {
			$name = 'Import_data('.$context.')'; //no translation
		} else {
			$name = $context;
		}
		$t = preg_replace(['/\s+/', '/__+/'], ['_', '_'], $name);
		if (extension_loaded('mbstring')) {
			$t = mb_convert_case($t, MB_CASE_LOWER, 'UTF-8');
		} else {
			$t = strtolower($t);
		}
		$alias = substr($t, 0, 16);

		$cfuncs = new Crypter($mod);
		$t = $cfuncs->decrypt_preference('default_password');
		$hash = $cfuncs->encrypt_value($t);

		$sql = 'INSERT INTO '.$pref.'module_auth_contexts (id,name,alias,default_password) VALUES (?,?,?,?)';
		$db->Execute($sql, [$cid, $name, $alias, $hash]);
		return $cid;
	}

	/**
	ImportUsers:
	Import user(s) data from uploaded CSV file. Can handle re-ordered columns.
	@mod: reference to current Auther module object
	@id: module ID
	@wanted: numeric id of context, or '*' for all contexts
	Returns: 2-member array, [0] = T/F indicating success, [1] = message
	*/
	public function ImportUsers(&$mod, $id, $wanted)
	{
		$filekey = $id.'csvfile';
		if (isset($_FILES) && isset($_FILES[$filekey])) {
			$file_data = $_FILES[$filekey];
			$parts = explode('.', $file_data['name']);
			$ext = end($parts);
			if ($file_data['type'] != 'text/csv'
			 || !($ext == 'csv' || $ext == 'CSV')
				 || $file_data['size'] <= 0 || $file_data['size'] > 25600 //$max*1000
				 || $file_data['error'] != 0) {
				return [FALSE, $mod->Lang('err_file')];
			}
			$fh = fopen($file_data['tmp_name'], 'r');
			if (!$fh) {
				return [FALSE, $mod->Lang('err_perm')];
			}
			//basic validation of file-content
			$firstline = self::GetSplitLine($fh);
			if ($firstline == FALSE) {
				return [FALSE, $mod->Lang('err_file')];
			}
			//file-column-name to fieldname translation
			$translates = [
			 '#Context' => 'context_id', //interpreted
			 '#Login' => 'account',
			 'Password' => 'password', //interpreted
			 'Passhash' => 'passhash', //ditto
			 'PassReset' => 'passreset',
			 'Name' => 'name',
			 'MessageTo' => 'address',
			 'Update' => 'update' //not a real field, numeric user-id or some boolean
			];
			/* non-public
				=>addwhen
				=>lastuse
				=>nameswap
				=>active
			*/
			$t = count($firstline);
			if ($t < 1 || $t > count($translates)) {
				return [FALSE, $mod->Lang('err_file')];
			}
			//setup for interpretation
			$offers = []; //column-index to fieldname translator
			foreach ($translates as $pub => $priv) {
				$col = array_search($pub, $firstline);
				if ($col !== FALSE) {
					$offers[$col] = $priv;
				} elseif ($pub[0] == '#') {
					//name of compulsory fields has '#' prefix
					return [FALSE, $mod->Lang('err_file')];
				}
			}

			if (!function_exists('password_hash')) {
				include __DIR__.DIRECTORY_SEPARATOR.'password.php';
			}

			$pref = \cms_db_prefix();
			$db = \cmsms()->GetDb();
			//CHECKME cache for update-checks, dup-checks BUT should be no dup's in data here
//			$exist = $db->GetArray('SELECT id,account FROM '.$pref.'module_auth_users ORDER BY id');
//			$exist = [];

			$utils = new Utils();
			$afuncs = new Auth($mod); //context [re]set in loop
			$cfuncs = new Crypter($mod);

			$mpw = $cfuncs->decrypt_preference(Crypter::MKEY);
			$cached = [];
			$st = time(); //UTC stamp
			$skips = 0;
			$icount = 0;
			$randompass = FALSE; //temp password if needed for validation
			if (($hashcol = array_search('passhash', $offers)) === FALSE) {
				$hashcol = 100; //never matched
			}

			while (!feof($fh)) {
				$imports = self::GetSplitLine($fh);
				if ($imports) {
					$data = [];
					$password = FALSE; //if set, store via password_hash($password, PASSWORD_DEFAULT);
					$passhash = FALSE; //if set, store raw via unpack('H*',$passhash);
					$update = FALSE;
					foreach ($imports as $i => $one) {
						$k = $offers[$i];
						$t = trim($one);
						if ($t) {
							switch ($k) {
							 case 'context_id':
								if (is_numeric($t)) {
									$data[$k] = (int)$t;
								} else {
									$data[$k] = $t;
								}
								break;
							 case 'account':
							 case 'name':
							 case 'address':
								$data[$k] = $t;
								break;
							 case 'passhash':
							 case 'password':
								$$k = $t; //park pending further processing
								break;
							case 'passreset':
								$data[$k] = !($t == 'no' || $t == 'NO');
								break;
							 case 'update':
								if (is_numeric($t)) {
									$update = (int)$t;
								} else {
									$update = !($t == 'no' || $t == 'NO');
								}
								break;
							default:
								return [FALSE, $mod->Lang('err_file')];
							}
						} else {
							switch ($k) {
							 case 'password':
								if ($passhash || !empty($imports[$hashcol])) {
									if (!$randompass) {
										$randompass = $utils->RandomString(32, FALSE);
									}
									$password = $randompass; //something to use during validation
								} else {
									$password = self::DEFAULTPASS; //placeholder
								}
								break;
							 case 'passhash': //ignore these
							 case 'passreset':
							 case 'update':
								break;
							 default:
								$data[$k] = NULL;
								break;
							}
						}
					}

					$t = $data['context_id'];
					if ($t) {
						if (array_key_exists($t, $cached)) {
							$cid = $cached[$t];
						} else {
							$cid = $utils->ContextID($t);
							if ($cid) {
								$cached[$cid] = $cid;
							} else {
								$cid = $this->MakeContext($mod, $t, $db, $pref);
								$cached[$t] = $cid;
							}
						}
					} elseif (array_key_exists('oopsanon', $cached)) {
						$cid = $cached['oopsanon'];
					} else {
						$cid = $this->MakeContext($mod, $mod->Lang('missing_name'), $db, $pref);
						$cached['oopsanon'] = $cid;
					}

					if (!($wanted == '*' || $wanted == $cid)) {
						++$skips;
						continue; //too bad about any newly-created context(s)!
					}

					$afuncs->SetContext($cid);

					if ($password == self::DEFAULTPASS) {
						$t = $afuncs->GetConfig('default_password'); //plaintext
						if ($t) {
							$password = $t;
						}
					}
					$res = $afuncs->ValidateAll([
						'account' => $data['account'],
						'password' => $password, //temp random value if raw password is to be installed
						'name' => $data['name'],
						'address' => $data['address'],
					], FALSE, TRUE);  //NO $except BUT $explicit
					//CHECKME also string-sanitization as relevant
					if ($res[0]) {
						$data['context_id'] = $cid;
						$data['passhash'] = $passhash ?
							pack('H*', $passhash) : password_hash($password, PASSWORD_DEFAULT);
						$login = $data['account'];
						$data['account'] = $cfuncs->cloak_value($login, 16, $mpw);
						$data['acchash'] = $cfuncs->hash_value($login, $mpw);
						$data['name'] = $cfuncs->cloak_value($data['name'], 0, $mpw);
						$data['address'] = $cfuncs->cloak_value($data['address'], 24, $mpw);

						$done = FALSE;
						if ($update) { //TODO robust UPSERT
							if (is_numeric($update)) {
								$sql = 'SELECT id FROM '.$pref.'module_auth_users WHERE id=?';
								$uid = $db->GetOne($sql, [$update]);
							} else {
								$uid = FALSE;
							}
							if (!$uid && $login) {
								$sql = 'SELECT id FROM '.$pref.'module_auth_users WHERE acchash=?';
								$uid = $db->GetOne($sql, [$data['acchash']]);
							}
							if ($uid) {
								$namers = implode('=?,', array_keys($data));
								$sql = 'UPDATE '.$pref.'module_auth_users SET '.$namers.'=? WHERE id=?';
								$args = array_values($data);
								$args[] = $uid;
								$db->Execute($sql, $args);
								if ($db->Affected_Rows() > 0) {
									++$icount;
									$done = TRUE;
								}
							}
						}
						if (!$done) {
							$namers = implode(',', array_keys($data));
							$fillers = str_repeat('?,', count($data) - 1);
							$sql = 'INSERT INTO '.$pref.'module_auth_users (id,'.$namers.',addwhen) VALUES (?,'.$fillers.'?,?)';
							$args = array_values($data);
							$uid = $db->GenID($pref.'module_auth_users_seq');
							array_unshift($args, $uid);
							$args[] = $st;
							$db->Execute($sql, $args);
							if ($db->Affected_Rows() > 0) {
								++$icount;
							} else {
								return [FALSE, $mod->Lang('err_system')];
							}
						}
					} else {
						++$skips;
					}
				}
			}
			fclose($fh);

			if ($skips) {
				return [FALSE, $mod->Lang('import_fails', $skips)];
			}
			if ($icount) {
				return [TRUE, $mod->Lang('import_count', $icount)];
			}
			return [FALSE, $mod->Lang('import_count', 0)];
		}
		return [FALSE, $mod->Lang('err_system')];
	}
}
