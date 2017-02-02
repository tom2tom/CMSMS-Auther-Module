<?php
#----------------------------------------------------------------------
# Module: Booker - a resource booking module
# Library file: CSV - functions for import/export of module data
#----------------------------------------------------------------------
# See file Booker.module.php for full details of copyright, licence, etc.
#----------------------------------------------------------------------
namespace Auther;

class Import
{
	private $cfuncs = FALSE; //Crypter-class object
	private $afuncs = FALSE; //Auth-class object

	private function ToChr($match)
	{
		$st = ($match[0][0] == '&') ? 2:1;
		return chr(substr($match[0],$st,2));
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
			$fields = fgetcsv($fh,4096);
			if (is_null($fields) || $fields == FALSE)
				return FALSE;
		} while (!isset($fields[1]) && is_null($fields[0])); //blank line
		$some = FALSE;
		//convert any separator supported by exporter
		foreach ($fields as &$one) {
			if ($one) {
				$some = TRUE;
				$one = trim(preg_replace_callback(
					['/&#\d\d;/','/%\d\d%/'], [$this,'ToChr'], $one));
			}
		}
		unset($one);
		if ($some)
			return $fields;
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
		$t = strtolower(preg_replace(['/\s+/', '/__+/'], ['_', '_'], $name));
		$alias = substr($t, 0, 16);
		$pw = $this->cfuncs->decrypt_preference($mod, 'default_password');
		$hash = $this->cfuncs->encrypt_value($mod, $pw);

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
			$parts = explode('.',$file_data['name']);
			$ext = end($parts);
			if ($file_data['type'] != 'text/csv'
			 || !($ext == 'csv' || $ext == 'CSV')
				 || $file_data['size'] <= 0 || $file_data['size'] > 25600 //$max*1000
				 || $file_data['error'] != 0) {
				return [FALSE, $mod->Lang('err_file')];
			}
			$fh = fopen($file_data['tmp_name'],'r');
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
			 '#Context'=>'context', //interpreted
			 '#Login'=>'publicid',
			 'Password'=>'passhash', //interpreted
//			 'Passhash'=>'passhash',
			 'Name'=>'name',
			 'MessageTo'=>'address',
			 'Update'=>'update' //not a real field, numeric user-id or some boolean
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
			foreach ($translates as $pub=>$priv) {
				$col = array_search($pub,$firstline);
				if ($col !== FALSE)
					$offers[$col] = $priv;
				elseif ($pub[0] == '#') {
					//name of compulsory fields has '#' prefix
					return [FALSE, $mod->Lang('err_file')];
				}
			}

			$pref = \cms_db_prefix();
			$db = \cmsms()->GetDb();
			//for update checks
			$exist = $db->GetArray('SELECT id,publicid FROM '.$pref.'module_auth_users ORDER BY id'); //TODO use this for dup-check

			$utils = new Utils();
			$this->afuncs = new Auth($mod); //context [re]set in loop
			$this->cfuncs = new Crypter();

			$masterkey = $this->cfuncs->decrypt_preference($mod, 'masterpass');;
			$cached = [];
			$st = time(); //UTC stamp
			$skips = 0;
			$icount = 0;

			while (!feof($fh)) {
				$imports = self::GetSplitLine($fh);
				if ($imports) {
					$data = [];
					$update = FALSE;
					foreach ($imports as $i=>$one) {
						$k = $offers[$i];
						if ($one) {
							switch ($k) {
							 case 'context':
							 	if (is_numeric($one)) {
									$data[$k] = (int)$one;
								} else {
	 								$data[$k] = trim($one);
								}
								break;
							 case 'publicid':
							 case 'passhash':
							 case 'name':
							 case 'address':
 								$data[$k] = trim($one);
								break;
							 case 'update':
							 	if (is_numeric($one)) {
									$update = (int)$one;
								} else {
									$update = !($one == 'no' || $one == 'NO');
								}
								break;
							default:
								return [FALSE, $mod->Lang('err_file')];
							}
						} else {
							switch ($k) {
							 case 'update': //ignore this
								break;
							 default:
 								$data[$k] = NULL;
								break;
							}
						}
					}

					$t = $data['context'];
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
						$skips++;
						continue; //too bad about any newly-created context(s)!
					}

					$this->afuncs->setContext($cid);

					$res = $this->afuncs->validateLogin($data['publicid']);
					$save = $res[0];
					$res = $this->afuncs->validatePassword($data['passhash']);
					$save = $save && $res[0];
					$res = $this->afuncs->validateAddress($data['address']);
					$save = $save && $res[0];

					if ($save) {
						$data['context'] = $cid;
						$data['passhash'] = password_hash($data['passhash'], PASSWORD_DEFAULT);
						$data['name'] = $this->cfuncs->encrypt_value($mod, $data['name'], $masterkey);
						$data['address'] = $this->cfuncs->encrypt_value($mod, $data['address'], $masterkey);

						$done = FALSE;
						if ($update) { //TODO robust UPSERT
							if (is_numeric($update)) {
								$sql = 'SELECT id FROM '.$pref.'module_auth_users WHERE id=?';
								$uid = $db->GetOne($sql,[$update]);
							} else {
								$uid = FALSE;
							}
							if (!$uid) {
								if ($data['publicid']) {
									$sql = 'SELECT id FROM '.$pref.'module_auth_users WHERE publicid=?';
									$uid = $db->GetOne($sql,[$data['publicid']]);
								} else {
									$uid = FALSE;
								}
							}
							if ($uid) {
								$namers = implode('=?,',array_keys($data));
								$sql = 'UPDATE '.$pref.'module_auth_users SET '.$namers.'=? WHERE id=?';
								$args = array_values($data);
								$args[] = $uid;
								if ($db->Execute($sql,$args)) {
									$icount++;
									$done = TRUE;
								}
							}
						}
						if (!$done) {
							$namers = implode(',',array_keys($data));
							$fillers = str_repeat('?,',count($data)-1);
							$sql = 'INSERT INTO '.$pref.'module_auth_users (id,'.$namers.',addwhen) VALUES (?,'.$fillers.'?,?)';
							$args = array_values($data);
							$uid = $db->GenID($pref.'module_auth_users_seq');
							array_unshift($args,$uid);
							$args[] = $st;
							if ($db->Execute($sql,$args)) {
								$icount++;
							} else {
								return [FALSE, $mod->Lang('err_system')];
							}
						}
					} else {
						$skips++;
					}
				}
			}
			fclose($fh);

			if ($skips)
				return [FALSE, $mod->Lang('import_fails', $skips)];
			if ($icount)
				return [TRUE, $mod->Lang('import_count', $icount)];
			return [FALSE, $mod->Lang('import_count', 0)];
		}
		return [FALSE, $mod->Lang('err_system')];
	}
}
