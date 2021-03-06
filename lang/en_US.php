<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$lang['accessdenied'] = 'Access denied. You don\'t have %s permission.';
$lang['account_inactive'] = 'Account has not yet been activated';
$lang['activate'] = 'Activate';
$lang['activatekey_expired'] = 'Activation key has expired'; //type-specific prefix
//$lang['activation_created'] = 'Account activation request has been created';
$lang['activation_challenged'] = 'Account activation message sent to recorded address';
$lang['activation_success'] = 'Account activated successfully';
$lang['addcontext'] = 'Add new context';
$lang['adduser'] = 'Add new user';
$lang['admindescription'] = 'This module provides authentication functionality for other modules';
$lang['alias'] = 'Alias';
$lang['all'] = 'All';
$lang['allpermitted'] = 'Everyone permitted';

//$lang['blank_same'] = 'If blank/empty, your current setting will remain';
$lang['blank_same2'] = 'For any replacement that is blank/empty, the current value will be retained';

/* challenges TODO
$lang[''] = 'Open precribed URL'
$lang[''] = 'Report browser-delivered token'
$lang[''] = 'Report separately-delivered token'
$lang[''] = 'Report delivered PIN'
$lang[''] = 'Answer security question'
$lang[''] = 'Proof of self'
*/
$lang['cancel'] = 'Cancel';
$lang['change_success'] = 'Account details changed';
$lang['close'] = 'Close';
$lang['compulsory_items'] = 'Properties marked with a <strong>*</strong> are compulsory.' ;
$lang['confirm'] = 'Are you sure ?';
$lang['confirm_del'] = 'Are you sure you want to delete \\\'%s\\\'?'; //double-escaped for use in js
$lang['confirm_delsel'] = 'Are you sure you want to delete selected context(s)?';
$lang['confirm_delsel2'] = 'Are you sure you want to delete selected user(s)?';
$lang['contact_opt'] = 'Contact (optional)';
$lang['current_typed'] = '<i>CURRENT</i> %s';

$lang['default'] = 'Default';
$lang['delete'] = 'Delete';
$lang['delete_challenged'] = 'Account deletion message sent to recorded address';
$lang['delete_success'] = 'Account deleted successfully';

$lang['email_banned'] = 'The specified email address is not allowed';
$lang['email_changed'] = 'Email address changed successfully';
/*
activate'
change'
delete'
recover'
reset'
*/
//'spaced' ('activate' etc) strings for various tasks, to be included in email/text messages
$lang['body_do_activate'] = 'activate your account';
$lang['body_do_change'] = 'change your account';
$lang['body_do_delete'] = 'delete your account';
$lang['body_do_recover'] = 'reinstate your password';
$lang['body_do_reset'] = 'reset your password';

$lang['body_request_activate'] = 'sign up';
$lang['body_request_change'] = 'request any change';
$lang['body_request_delete'] = 'request such deletion';
$lang['body_request_recover'] = 'initiate password recovery';
$lang['body_request_reset'] = 'request a password reset';

$lang['email_subject_activate'] = 'Activate account';
$lang['email_subject_change'] = 'Change account details';
$lang['email_subject_delete'] = 'Delete account';
$lang['email_subject_recover'] = 'Reinstate password';
$lang['email_subject_reset'] = 'Reset password';
//templates which include relevant parts from those above
$lang['email_subject'] = '%s - %s';
$lang['email_token_body'] = 'Hello,<br /><br />To %s on the %s, you will need to use the following token:<br /><br />%s<br /><br />If you did not %s recently, something or somebody has misbehaved, so you should keep watch on your account.';
$lang['email_token_altbody'] = 'Hello,'."\n\n".'To %s on the %s, you will need to use the following token:'."\n\n".'%s'."\n\n".'If you did not %s recently, something or somebody has misbehaved, so you should keep watch on your account.';
$lang['email_url_body'] = 'Hello,<br /><br />To %s on the %s, click <a href="%s">this link</a>.<br /><br />If you did not %s recently, something or somebody has misbehaved, so you should keep watch on your account.';
$lang['email_url_altbody'] = 'Hello,'."\n\n".'To %s on the %s, visit the following URL:'."\n".' %s'."\n\n".'If you did not %s recently, something or somebody has misbehaved, so you should keep watch on your account.';
//ibid for SMS messages
$lang['text_token_body'] = 'To %s on the %s, use the following token: %s';
$lang['text_url_body'] = 'To %s on the %s, visit: %s';

//VARIOUS ERRORS
$lang['err_ajax'] = 'Server communication error';
//$lang['err_baduser'] = 'Missing or unrecognised user';
$lang['err_captcha'] = 'The entered captcha text was wrong';
//$lang['user_verify_failed'] = 'Captcha text is not valid';
//$lang['err_data'] = 'No data';
//$lang['err_dup'] = 'Nominated time already booked';
$lang['err_file'] = 'Inappropriate file specified';
$lang['err_parm'] = 'Parameter error';
$lang['err_perm'] = 'No permission';
//$lang['err_server'] = 'Server error';
$lang['err_system'] = 'System error';
//$lang['err_'] = 'The email address is not valid';
//$lang['err_'] = 'The login is not available';
//$lang['err_'] = 'The password entries are not the same';
//$lang['err_'] = 'The password is too easy to crack';
$lang['err_text']='Invalid SMS content';
$lang['already_activated'] = 'Account is already activated';
$lang['incorrect_type'] = '%s is wrong';
$lang['incorrect_activatekey'] = 'Activation token is wrong'; //type-specific *key
//$lang['incorrect_email'] = 'Email address is incorrect';
//$lang['incorrect_login'] = 'Login name is not recognised';
//$lang['incorrect_password'] = 'Password is wrong';
$lang['incorrect_resetkey'] = 'Reset token is wrong'; //type-specific *key
$lang['incorrect_vague'] = 'Unrecognised login and/or password';
$lang['invalid_type'] = '%s is not valid';
$lang['invalid_activatekey'] = 'Activation token is not valid'; //type-specific *key
//$lang['invalid_email'] = 'Email address is not valid';
//$lang['invalid_newpassword'] = 'New password must contain at least one uppercase and lowercase character, and at least one digit';
//$lang['invalid_remember_me'] = 'The remember me field is not valid';
$lang['invalid_resetkey'] = 'Reset token is not valid'; //type-specific *key
//$lang['login_long'] = 'Login name is too long';
$lang['login_short'] = 'Login name is too short';
$lang['login_taken'] = 'Login name is already in use';
$lang['login_taken2'] = 'Login \'%s\' is not available, but you could use \'%s\' instead';
$lang['newemail_match'] = 'New email matches previous email';
$lang['newpassword_long'] = 'New password is too long';
$lang['newpassword_match'] = 'New password is the same as the old password';
$lang['newpassword_nomatch'] = 'New passwords do not match';
$lang['newpassword_short'] = 'New password is too short';
$lang['password_nomatch'] = 'Passwords do not match';
$lang['password_short'] = 'Password is too short';
$lang['password_weak'] = 'Password is too easy to crack';
$lang['request_exists'] = 'A request already exists';
$lang['resetkey_expired'] = 'Reset key has expired'; //type-specific prefix
$lang['want_email'] = 'Login or contact must be a valid email address';

$lang['first'] = 'First';
$lang['friendlyname'] = 'Authenticator';
$lang['function_disabled'] = 'This function has been disabled';

$lang['help_address_required'] = '';
$lang['help_alias'] = 'For identifying and selecting this context at runtime. If left blank, an alias will be derived from tne name.';
$lang['help_attack_mitigation_span'] = 'Length of time that login-attempt data are retained, something like \'10 minutes\' or \'1 day\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
$lang['help_ban_count'] = 'After this many failed attemts, a user is locked-out for the specified \'attack-protection interval\'. 0 disables this protection.';
$lang['help_contact'] = 'Must be a valid email address';
$lang['help_contact2'] = 'Typically an email address or cell/mobile phone number';
$lang['help_context_address'] = 'Above information about sender name appplies here too';
$lang['help_context_sender'] = 'Typically this will be blank/empty, to use the mailer-default value. Otherwise set to a value supported by the mailer module, or else message transmission may be blocked.';
$lang['help_context_site'] = 'For use in confirmation-messages';
//$lang['help_cookie_domain'] = ''; see http://php.net/manual/en/function.setcookie.php
$lang['help_cookie_forget'] = 'Length of time that a login is tracked, if [TODO], something like \'2 hours\' or \'1 week\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
//$lang['help_cookie_http'] = '';
$lang['help_cookie_name'] = '';
//$lang['help_cookie_path'] = '';
$lang['help_cookie_remember'] = 'Length of time that a user login persists, something like \'2 hours\' or \'1 week\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
//$lang['help_cookie_secure'] = '';
$lang['help_default_password'] = 'Applied if necessary when adding or importing users';
$lang['help_email_banlist'] = '';
$lang['help_email_domains'] = 'Comma-separated series of email domains, e.g. \'msn.com,gmail.com\' to use instead of the default values used by the mailcheck script for initial address-validation';
$lang['help_email_login'] = 'A poor choice if email is shared e.g. in families';
$lang['help_email_required'] = 'Either username or contact <strong>must</strong> be a valid email address';
$lang['help_email_subdomains'] = 'Comma-separated series of partial domains, e.g. \'yahoo,hotmail\' to use instead of the default values used by the mailcheck script for secondary address-validation';
$lang['help_email_topdomains'] = 'Comma-separated series of top domains, e.g. \'com,com.tw,de,net,net.au\' to use instead of the default values used by the mailcheck script for final address-validation';
$lang['help_password_rescue'] = '';
$lang['help_identifier'] = 'Personal name, email address or some other unique identifier';
$lang['help_login_max_length'] = 'Blank or 0 means no limit';
$lang['help_login_min_length'] = 'Blank or 0 means no limit';
$lang['help_login'] = 'Perhaps an email address, or some other unique descriptor';
$lang['help_masterpass'] = '';
$lang['help_message_charset'] = '';
$lang['help_name_required'] = '';
$lang['help_nameswap'] = 'which means the last part is for personal/friendly addressing';
$lang['help_owner'] = 'Admin user assigned to manage this context';
$lang['help_password'] = 'At least %d characters, and not too predictable';
$lang['help_password_forget'] = 'Length of time between forced password-resets, something like \'1 month\' or \'2 weeks\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>), or if blank/empty, no expiry';
$lang['help_password_min_length'] = '';
$lang['help_password_min_score'] = 'Number 1..5 broadly indicating the difficulty of cracking a password (1 is easiest)';
$lang['help_password_new'] = 'When provided, must have length &gt;= %d and complexity-score &gt= %d';
$lang['help_password_recover'] = 'A temporary password token has been sent to your address. Retrieve that token, and insert it above.';
$lang['help_password_reset'] = 'Require password to be renewed at next login';
//$lang['help_password_token'] = 'The temporary password token sent to your address';
$lang['help_raise_count'] = 'After this many failed attempts, a user is required to provide extra authentication. 0 disables this protection.';
$lang['help_recaptcha_key'] = 'Token obtained from <a href="https://www.google.com/recaptcha/admin#list">Google</a>. If this is not provided, level 1 authentication will be much less friendly.';
$lang['help_recaptcha_secret'] = 'Private/secret token complementing the public token entered above';
$lang['help_request_key_expiration'] = 'Length of time before sent confirmation-requests expire, something like \'10 minutes\' or \'1 day\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
$lang['help_security_level'] = 'Determines the process for, and extent of security-checking during, logins etc';
//$lang['help_send_activate_message'] = '';
//$lang['help_send_reset_message'] = '';
$lang['help_sms_prefix']='One or more numbers e.g. 1 for USA. <a href="http://countrycode.org">Search</a>';

$lang['id'] = 'ID';
$lang['import_count'] = '%s item(s) imported';
$lang['import_fails'] = '%s item(s) could not be imported';
$lang['import'] = 'Import';

$lang['last'] = 'Last';
$lang['level_NOBOT'] = 'Anonymous non-robot';
$lang['level_LOSEC'] = 'Login+password';
$lang['level_MIDSEC'] = 'Login+password enhanced';
$lang['level_CHALLENGED'] = 'Challenged';
$lang['level_HISEC'] = 'Advanced'; //TODO
$lang['logged_in'] = 'You are now logged in';
$lang['logged_out'] = 'You are now logged out';
$lang['lostpass'] = 'or if password is lost, click this';
$lang['lostpass_renew'] = 'If password is lost, you\'ll need to re-register';

$lang['meaning_type'] = 'Did you mean %s ?';
$lang['missing_address'] = 'No address';
$lang['missing_contact'] = 'No contact';
$lang['missing_login'] = 'No login';
$lang['missing_name'] = 'No name yet';
$lang['missing_type'] = '%s must be provided';
$lang['module_nav'] = 'Module mainpage';

//$lang['NA'] = 'Not applicable';
$lang['name_for'] = 'for the \'%s\' context';
$lang['name'] = 'Name';
$lang['name_opt'] = 'Name (optional)';
$lang['name_to'] = 'to the \'%s\' context';
$lang['new_typed'] = '<i>REPLACEMENT</i> %s';
$lang['next'] = 'Next';
$lang['noauth'] = 'Nothing is required for this';
$lang['nocontext'] = 'No context has been registered';
$lang['none'] = 'None';
$lang['no'] = 'No';
$lang['not_contactable'] = 'No suitable contact address is recorded';
$lang['notpermitted'] = 'Not permitted';
$lang['nouser'] = 'No user has been registered for the \'%s\' context';

$lang['pageof'] = 'Page %s of %s';
$lang['pagerows'] = 'rows per page';
$lang['password'] = 'Password';
$lang['password_changed'] = 'Password changed successfully';
$lang['password_reset'] = 'Password reset successfully';
$lang['perm_modcontext'] = 'Modify Authentication Contexts';
$lang['perm_modify'] = 'Modify Authentication Module Properties';
$lang['perm_moduser'] = 'Modify Authenticated Users';
$lang['perm_see'] = 'Review Authentication Data';
//$lang['perm_send'] = 'Send Authentication Events';
$lang['perm_some'] = 'some relevant';
$lang['postinstall'] = 'Authenticator module installed sucessfully.<br />Be sure to set relevant permissions';
$lang['postuninstall'] = 'Authenticator module uninstalled';
$lang['previous'] = 'Previous';
$lang['proceed'] = 'Proceed';

$lang['really_uninstall'] = 'Are you sure you want to uninstall the Authenticator module?';
$lang['register_challenged'] = 'Account activation message sent to recorded address';
$lang['register_success'] = 'Account created successfully';
$lang['rememberme'] = 'The remember me field';
//$lang['reset_created'] = 'Password reset request has been created';
$lang['reset_challenged'] = 'Password reset message sent to recorded address';
$lang['reset_now'] = 'Your password must be reset now';
$lang['reregister'] = 'After so many failed attempts, you might like to re-register.';
$lang['reregister2'] = 'Too many failed attempts. You\'ll need to re-register.';
$lang['reset'] = 'Reset';
$lang['retry'] = 'Try again';

$lang['submit'] = 'Submit';
$lang['system_error'] = 'A system error (%s) has been encountered. Please try again.';

$lang['temp_notsent'] = 'Cannot send information to your address. You\'ll need to re-register.';
$lang['temp_sent'] = 'A temporary token has been sent to your address. Insert that token below, along with your replacement.';
//$lang['temp_typed'] = '<i>TEMPORARY</i> %s';

$lang['tip_activeuser'] = 'toggle the active flag for each selected user';
$lang['tip_delcontext'] = 'delete selected context(s)';
$lang['tip_delete'] = 'delete this';
$lang['tip_deluser'] = 'delete selected user(s)';
$lang['tip_edit'] = 'edit properties';
$lang['tip_importuser'] = 'import user(s) from file';
$lang['tip_resetuser'] = 'toggle the force-password-reset flag for each selected user';
$lang['tip_usersedit'] = 'review/change users';
$lang['tip_users'] = 'review users';
$lang['tip_view'] = 'review properties';

$lang['title_active'] = 'Active';
$lang['title_addressable'] = 'Contactable';
$lang['title_address_required'] = 'Each user must provide her/his contact-address';
$lang['title_alias'] = 'Alias';
$lang['title_attack_mitigation_span'] = 'Attack-protection interval';
$lang['title_ban_count'] = 'Login (etc) attempts before block';
$lang['title_captcha'] = 'I\'m not a robot';
$lang['title_captcha2'] = 'enter the displayed text';
$lang['title_captcha3'] = 'Captcha text';
$lang['title_challenges'] = 'Challenges';
$lang['title_changes'] = 'CHANGES';
$lang['title_completed'] = 'Completed';
$lang['title_contact'] = 'Contact';
$lang['title_contextadd'] = 'Add authentication-context';
$lang['title_context_address'] = 'Email-address used as messages source';
$lang['title_contextfull'] = 'Authentication-context properties';
$lang['title_contexts'] = 'Contexts';
$lang['title_context_sender'] = 'Name of email-notice sender';
$lang['title_context_site'] = 'Website name';
//$lang['title_cookie_domain'] = '';
$lang['title_cookie_forget'] = 'Login/session tracking-data retention';
//$lang['title_cookie_http'] = '';
$lang['title_cookie_name'] = 'Name of http cookie which tracks logins';
//$lang['title_cookie_path'] = '';
$lang['title_cookie_remember'] = 'Login/session duration';
//$lang['title_cookie_secure'] = '';
$lang['title_default_password'] = 'Default user-password';
$lang['title_email_banlist'] = 'Prevent blacklisted email addresses';
$lang['title_email_domains'] = 'Email-address-check domains';
$lang['title_email'] = 'Email address';
$lang['title_email_login'] = 'User-identifier must be an email-address';
$lang['title_email_required'] = 'Require an email-address';
$lang['title_email_subdomains'] = 'Email-address-check sub-domains';
$lang['title_email_topdomains'] = 'Email-address-check top-level domains';
$lang['title_enterdetails'] = 'Enter your details';
$lang['title_entertyped'] = 'Enter %s';
$lang['title_password_rescue'] = 'Enable password recovery';
$lang['title_identifier'] = 'Login name';
$lang['title_id'] = 'ID';
$lang['title_import'] = 'Import user-data from file';
$lang['title_lastuse'] = 'Latest login';
$lang['title_login_max_length'] = 'User-identifier maximum length';
$lang['title_login_min_length'] = 'User-identifier minimum length';
$lang['title_login'] = 'Username / login';
$lang['title_masterpass']='Pass-phrase for securing sensitive data';
$lang['title_message_charset'] = 'Character encoding in email messages';
$lang['title_name'] = 'Name';
$lang['title_name_required'] = 'Each user must provide her/his name';
$lang['title_nameswap'] = 'Name begins with family-name';
$lang['title_owner'] = 'Owner';
$lang['title_passagain'] = 'Password (again)';
$lang['title_password_forget'] = 'Password lifetime';
$lang['title_password_min_length'] = 'Minimum password-length';
$lang['title_password_min_score'] = 'Password-complexity minimum score';
$lang['title_password_new'] = 'Replacement password';
//$lang['title_password_recover'] = 'Password reinstate';
$lang['title_password_reset'] = 'Password reset';
$lang['title_pending_reset'] = 'Reset<br />flagged';
$lang['title_password_token'] = 'Temporary password / token';
$lang['title_raise_count'] = 'Login (etc) attempts before extra attention';
$lang['title_recaptcha_key'] = 'reCaptcha public key';
$lang['title_recaptcha_secret'] = 'reCaptcha private key';
$lang['title_register'] = 'Registered';
$lang['title_request_key_expiration'] = 'Challenge-key lifetime';
$lang['title_security_level'] = 'Security level';
$lang['title_send_activate_message'] = 'Send account-activation emails';
$lang['title_send_reset_message'] = 'Send password-reset emails';
$lang['title_settings'] = 'Settings';
$lang['title_sms_prefix']='Country-code to be prepended to phone numbers';
$lang['title_useradd'] = 'Add user';
$lang['title_userfull'] = 'User properties';
$lang['title_usersfor'] = 'Registered users for \\\'%s\\\'';
$lang['token'] = 'Token';

$lang['upload'] = 'Upload';
$lang['user_blocked'] = 'You are locked out of the system for a while. Try again later.';
$lang['user_challenged'] = 'You are due to provide some further information';
$lang['users'] = 'Users';

$lang['wantjs'] = 'This process would be easier if javascript were enabled in your browser.';
$lang['yes'] = 'Yes';

$lang['event_Register_desc'] = <<<'EOS'
Event generated when a user registers successfully
EOS;
$lang['event_Register_help'] = <<<'EOS'
<p>An event generated when</p>
EOS;
$lang['event_Deregister_desc'] = <<<'EOS'
Event generated when a user-registration is cancelled
EOS;
$lang['event_Deregister_help'] = <<<'EOS'
<p>An event generated when</p>
EOS;
$lang['event_Login_desc'] = <<<'EOS'
Event generated when a user is successfully authorised
EOS;
$lang['event_Login_help'] = <<<'EOS'
<p>An event generated when</p>
EOS;
$lang['event_LoginFail_desc'] = <<<'EOS'
Event generated when a user fails to gain authorisation
EOS;
$lang['event_LoginFail_help'] = <<<'EOS'
<p>An event generated when</p>
EOS;
$lang['event_Logout_desc'] = <<<'EOS'
Event generated when a user ends her/his current authorisation
EOS;
$lang['event_Logout_help'] = <<<'EOS'
<p>An event generated when</p>
EOS;

$lang['help_import'] = <<<'EOS'
<h3>File format</h3>
<p>The input file must be in ASCII format with data fields separated by commas.
Any actual comma in a field should be represented by '&amp;#44;'.
Each line in the file (except the header line, discussed below) represents one user.</p>
<h4>Header line</h4>
<p>The first line of the file names the fields in the file, as follows.
The supplied names may be in any order. Those prefixed by a '#' represent compulsory values.<br />
<code>#Context,#Login,Password,Passhash,Name,MessageTo,Update</code></p>
<h4>Other lines</h4>
<p>The data in each line must conform to the header columns, of course. Any non-compulsory field, or entire line, may be empty.<br />
Context may be a numeric identifier or alias string, representing an authentication-context (which will be created if not already present).<br />
Passhash is a previously-exported password in encrypted form. If neither Password or Passhash is provided, a default password will be applied.<br />
MessageTo will typically be an email address.<br />
The Update field will be treated as TRUE if it contains something other than 0 or 'no' or 'NO' (no quotes, untranslated)<br />
<h3>Problems</h3>
<p>The import process will fail if:<ul>
<li>the first line field names are are not as expected</li>
<li>a compulsory-field value is not provided</li>
<li>a password is not sufficiently secure</li>
<li>an email address is malformed</li>
</ul></p>
EOS;
