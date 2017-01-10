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
					array('/&#\d\d;/','/%\d\d%/'),array($this,'ToChr'),$one));
			}
		}
		unset($one);
		if ($some)
			return $fields;
		return FALSE; //ignore lines with all fields empty
	}

	/**
	ImportUsers:
	Import user(s) data from uploaded CSV file. Can handle re-ordered columns.
	@mod: reference to current Booker module object
	@id: session identifier
	Returns: 2-member array, [0] = T/F indicating success, [1] = count of imports, or lang key for message
	*/
	public function ImportUsers(&$mod, $id)
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
				return array(FALSE,'err_file');
			}
			$fh = fopen($file_data['tmp_name'],'r');
			if (!$fh)
				return array(FALSE,'err_perm');
			//basic validation of file-content
			$firstline = self::GetSplitLine($fh);
			if ($firstline == FALSE) {
				return array(FALSE,'err_file');
			}
			//file-column-name to fieldname translation
			$translates = array(
			 '#Login'=>'publicid',
			 'Password'=>'passhash', //interpreted
			 'Passhash'=>'passhash',
			 'Email'=>'address',
			 '#Context'=>'context',
			 'Update'=>'update' //not a real field
			);
			/* non-public
				=>lastuse
				=>active
			*/
			$t = count($firstline);
			if ($t < 1 || $t > count($translates)) {
				return array(FALSE,'err_file');
			}
			//setup for interpretation
			$offers = array(); //column-index to fieldname translator
			foreach ($translates as $pub=>$priv) {
				$col = array_search($pub,$firstline);
				if ($col !== FALSE)
					$offers[$col] = $priv;
				elseif ($pub[0] == '#') {
					//name of compulsory fields has '#' prefix
					return array(FALSE,'err_file');
				}
			}
			$utils = new Utils();
			//for update checks
			$exist = $utils->SafeGet('SELECT booker_id,name,publicid FROM '.$mod->BookerTable.' ORDER BY booker_id',FALSE);

			$funcs = new Userops();
			$dt = new \DateTime('now',new \DateTimeZone('UTC'));
			$st = $dt->getTimestamp();
//			$skip = FALSE;
			$icount = 0;

			while (!feof($fh)) {
				$imports = self::GetSplitLine($fh);
				if ($imports) {
					$data = array();
					$save = FALSE;
					$update = FALSE;
					foreach ($imports as $i=>$one) {
						$k = $offers[$i];
						if ($one) {
							switch ($k) {
							 case 'name':
							 case 'publicid':
								$data[$k] = trim($one);
								$save = TRUE;
								break;
							 case 'passhash':
 								$t = trim($one);
								if ($translates[$i] == 'Password') {
									$data[$k] = $funcs->HashPassword($t);
									$save = TRUE;
								} elseif (empty($data[$k])) { //Passhash but no prior Password
									$data[$k] = ($t) ? $t : $funcs->HashPassword($t);
									$save = TRUE;
								}
								break;
							 case 'address':
 								$t = trim($one);
								if (!preg_match('/\w+@\w+\.\w+/',$t)) {
									return array(FALSE,'err_file');
								}
								$data[$k] = $t;
								$save = TRUE;
								break;
							 case 'phone':
 								$t = trim($one);
						 		if (!preg_match('/^(\+\d{1,4} *)?[\d ]{5,15}$/',$t)) {
									return array(FALSE,'err_file');
								}
								$data[$k] = $t;
								$save = TRUE;
								break;
							 case 'type':
								switch ($translates[$i]) {
							 	 case 'Postpayer':
								 	$t = ($one == 'no' || $one == 'NO') ? 0:10; //permission-flag
									break;
								 case 'Recorder':
								 	$t = ($one == 'no' || $one == 'NO') ? 0:20; //ditto
									break;
								 case 'Usertype':
									if (!is_numeric($one)) {
										return array(FALSE,'err_file');
									}
									$t = (int)$one;
									if ($t < 0 || $t > 9) //base-types 0..9
										$t = 0;
									break;
								}
								if (isset($data[$k]))
									$data[$k] += $t;
								else
									$data[$k] = $t;
								$save = TRUE;
								break;
							 case 'displayclass':
								if (!is_numeric($one)) {
									return array(FALSE,'err_file');
								}
								$t = (int)$one;
								if ($t < 1 || $t > \Booker::USERSTYLES)
									$t = 1;
								$data[$k] = $t;
								$save = TRUE;
								break;
							 case 'update':
							 	if (is_numeric($one)) {
									$update = (int)$one;
								} else {
									$update = !($one == 'no' || $one == 'NO');
								}
								break;
							default:
								return array(FALSE,'err_file');
							}
						} else {
							switch ($k) {
							 case 'type':
								if (!isset($data[$k])) {
									if ($translates[$i] == 'Usertype')
										$data[$k] = 0;
								}
								break;
							 case 'displayclass':
								$data[$k] = 1;
							 case 'update': //ignore this
								break;
							 default:
 								$data[$k] = NULL;
								break;
							}
						}
					}
					if ($save) {
						$done = FALSE;
						if ($update) { //TODO robust UPSERT
							if (is_numeric($update)) {
								$sql = 'SELECT booker_id FROM '.$mod->BookerTable.' WHERE booker_id=?';
								$bookerid = $utils->SafeGet($sql,array($update),'one');
							} else {
								$bookerid = FALSE;
							}
							if (!$bookerid) {
								$sql = 'SELECT booker_id FROM '.$mod->BookerTable;
								if ($data['publicid']) {
									$sql .= ' WHERE publicid=?';
									$args = array($data['publicid']);
									$bookerid = $utils->SafeGet($sql,$args,'one');
								} elseif ($data['name']) {
									$sql .= ' WHERE name=?';
									$args = array($data['name']);
									$bookerid = $utils->SafeGet($sql,$args,'one');
								} else {
									$bookerid = FALSE;
								}
							}
							if ($bookerid) {
								//TODO cache $bookerid=>$data['name'].$data['publicid']
								$namers = implode('=?,',array_keys($data));
								$sql = 'UPDATE '.$mod->BookerTable.' SET '.$namers.'=? WHERE booker_id=?';
								$args = array_values($data);
								$args[] = $bookerid;
								if ($utils->SafeExec($sql,$args)) {
									$icount++;
									$done = TRUE;
								}
							}
						}
						if (!$done) {
							$namers = implode(',',array_keys($data));
							$fillers = str_repeat('?,',count($data)-1);
							$sql = 'INSERT INTO '.$mod->BookerTable.' (booker_id,'.$namers.',addwhen) VALUES (?,'.$fillers.'?,?)';
							$args = array_values($data);
							$bookerid = $mod->dbHandle->GenID($mod->BookerTable.'_seq');
							array_unshift($args,$bookerid);
							$args[] = $st;
							if ($utils->SafeExec($sql,$args)) {
								$icount++;
							} else {
								return array(FALSE,'err_system');
							}
						}
//					} else {
//						$skip = TRUE;
					}
				}
			}
			fclose($fh);
//			if ($skip)
//				return array(FALSE,'warn_duplicate');
//			else
			if ($icount)
				return array(TRUE,$icount);
			return array(FALSE,'none');
		}
		return array(FALSE,'err_system');
	}
