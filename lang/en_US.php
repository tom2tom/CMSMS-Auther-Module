<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$lang['accessdenied'] = 'Access denied. You don\'t have %s permission.';
$lang['account_activated'] = 'Account activated';
$lang['account_deleted'] = 'Account deleted';
$lang['account_inactive'] = 'Account has not yet been activated';
$lang['activatekey_expired'] = 'Activation key has expired'; //type-specific prefix
$lang['activatekey_incorrect'] = 'Activation key is incorrect'; //type-specific prefix
$lang['activation_exists'] = 'An activation email has already been sent';
$lang['activation_sent'] = 'Activation email has been sent';
$lang['activationkey_invalid'] = 'Activation key is invalid';
$lang['addcontext'] = 'Add new context';
$lang['adduser'] = 'Add new user';
$lang['admindescription'] = 'This module provides authentication functionality for other modules';
$lang['alias'] = 'Alias';
$lang['allpermitted'] = 'Everyone permitted';
$lang['already_activated'] = 'Account is already activated';
$lang['authority_failed'] = 'Incorrect login and/or password';

$lang['cancel'] = 'Cancel';
$lang['close'] = 'Close';
$lang['compulsory_items'] = 'Properties marked with a <strong>*</strong> are compulsory.' ;
$lang['confirm_del'] = 'Are you sure you want to delete \\\'%s\\\'?'; //double-escaped for use in js
$lang['confirm_delsel'] = 'Are you sure you want to delete selected context(s)?';

$lang['delete'] = 'Delete';

$lang['email_activation_altbody'] = 'Hello,'."\n\n".'To be able to log in you first need to activate your account by visiting the following URL:'."\n".' %s'."\n\n".'If you did not sign up on %s recently then this message was sent in error, please ignore it.';
$lang['email_activation_body'] = 'Hello,<br /><br />To be able to log in you first need to activate your account by clicking on the following <a href="%s">link</a>.<br /><br />If you did not sign up on %s recently then this message was sent in error, please ignore it.';
$lang['email_activation_subject'] = '%s - Activate account';
$lang['email_banned'] = 'The specified email address is not allowed';
$lang['email_changed'] = 'Email address changed successfully';
$lang['email_incorrect'] = 'Email address is incorrect';
$lang['email_invalid'] = 'Email address is invalid';
$lang['email_reset_altbody'] = 'Hello,'."\n\n".'To reset your password, please visit the following URL:'."\n".' %s'."\n\n".'If you did not request a password reset on %s recently then this message was sent in error, please ignore it.';
$lang['email_reset_body'] = 'Hello,<br /><br />To reset your password, please click the following <a href="%s">link</a>.<br /><br />If you did not request a password reset on %s recently then this message was sent in error, please ignore it.';
$lang['email_reset_subject'] = '%s - Password reset request';

$lang['friendlyname'] = 'Authenticator';
$lang['function_disabled'] = 'This function has been disabled';
//$lang['help_address_required'] = '';
$lang['help_alias'] = 'For identifying and selecting this context at runtime. If left blank, an alias will be derived from tne name.';
$lang['help_attack_mitigation_span'] = 'Length of time that login-attempt data are retained, something like \'10 minutes\' or \'1 day\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
$lang['help_attempts_before_ban'] = 'After this many failed attemts, a user is locked-out for the specified \'attack-protection interval\'. 0 disables this protection.';
$lang['help_attempts_before_verify'] = 'After this many failed attemts, a user is required to provide extra authentication. 0 disables this protection.';
$lang['help_context_address'] = 'Above information about sender name appplies here too';
$lang['help_context_sender'] = 'Typically this will be blank/empty, to use the mailer-default value. Otherwise set to a value supported by the mailer module, or else message transmission may be blocked.';
//$lang['help_cookie_domain'] = ''; see http://php.net/manual/en/function.setcookie.php
$lang['help_cookie_forget'] = 'Length of time that a login is tracked, if [TODO], something like \'2 hours\' or \'1 week\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
//$lang['help_cookie_http'] = '';
//$lang['help_cookie_name'] = '';
//$lang['help_cookie_path'] = '';
$lang['help_cookie_remember'] = 'Length of time that a user login persists, something like \'2 hours\' or \'1 week\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
//$lang['help_cookie_secure'] = '';
//$lang['help_email_required'] = '';
//$lang['help_email_banlist'] = '';
//$lang['help_forget_rescue'] = '';
$lang['help_login_max_length'] = 'Blank or 0 means no limit';
$lang['help_login_min_length'] = 'Blank or 0 means no limit';
//$lang['help_message_charset'] = '';
//$lang['help_masterpass'] = '';
//$lang['help_password_min_length'] = '';
$lang['help_owner'] = 'Admin user assigned to manage this context';
$lang['help_password_min_score'] = 'Number 1..5 broadly indicating the difficulty of cracking a password (1 is easiest)';
$lang['help_request_key_expiration'] = 'Length of time before sent confirmation-requests expire, something like \'10 minutes\' or \'1 day\' (unquoted, in english that <a href="http://php.net/manual/en/datetime.formats.relative.php">PHP understands</a>)';
$lang['help_security_level'] = 'Number 1..4 which determines the process for, and extent of security-checking during, logins (1 is lowest)';
//$lang['help_send_activate_message'] = '';
//$lang['help_send_reset_message'] = '';

$lang['id'] = 'ID';
$lang['import'] = 'Import';

$lang['logged_in'] = 'You are now logged in';
$lang['logged_out'] = 'You are now logged out';
$lang['login_incorrect'] = 'Login name is not recognised';
//$lang['login_long'] = 'Login name is too long';
$lang['login_notvalid'] = 'Login name is invalid';
$lang['login_short'] = 'Login name is too short';
$lang['login_taken'] = 'Login name is already in use';

$lang['missingname'] = 'No name yet';
$lang['module_nav'] = 'Module mainpage';

//$lang['NA'] = 'Not applicable';
$lang['name'] = 'Name';
$lang['newemail_match'] = 'New email matches previous email';
$lang['newpassword_invalid'] = 'New password must contain at least one uppercase and lowercase character, and at least one digit';
$lang['newpassword_long'] = 'New password is too long';
$lang['newpassword_match'] = 'New password is the same as the old password';
$lang['newpassword_nomatch'] = 'New passwords do not match';
$lang['newpassword_short'] = 'New password is too short';
$lang['nocontext'] = 'No context has been registered';
$lang['nouser'] = 'No user has been registered for the \'%s\' context';

$lang['password_changed'] = 'Password changed successfully';
$lang['password_incorrect'] = 'Password is wrong';
$lang['password_nomatch'] = 'Passwords do not match';
$lang['password_notvalid'] = 'Password is invalid';
$lang['password_reset'] = 'Password reset successfully';
$lang['password_short'] = 'Password is too short';
$lang['password_weak'] = 'Password is too weak';
$lang['perm_modify'] = 'Modify Authentication Module Properties';
$lang['perm_modcontext'] = 'Modify Authentication Contexts';
$lang['perm_moduser'] = 'Modify Authenticated Users';
$lang['perm_see'] = 'Review Authentication Data';
//$lang['perm_send'] = 'Send Authentication Events';
$lang['perm_some'] = 'some relevant';
$lang['postinstall'] = 'Authenticator module installed sucessfully.<br />Be sure to set relevant permissions';
$lang['postuninstall'] = 'Authenticator module uninstalled';

$lang['really_uninstall'] = 'Are you sure you want to uninstall the Authenticator module?';
$lang['register_success'] = 'Account created. Activation email sent to email';
$lang['register_success_emailmessage_suppressed'] = 'Account created';
$lang['remember_me_invalid'] = 'The remember me field is invalid';
$lang['reset_exists'] = 'A reset request already exists';
$lang['reset_requested'] = 'Password reset request sent to email address';
$lang['reset_requested_emailmessage_suppressed'] = 'Password reset request has been created';
$lang['resetkey_expired'] = 'Reset key has expired'; //type-specific prefix
$lang['resetkey_incorrect'] = 'Reset key is incorrect'; //type-specific prefix
$lang['resetkey_invalid'] = 'Reset key is invalid';

$lang['submit'] = 'Submit';
$lang['system_error'] = 'A system error has been encountered. Please try again.';

$lang['tip_delete'] = 'delete this';
$lang['tip_delcontext'] = 'delete selected context(s)';
$lang['tip_deluser'] = 'delete selected user(s)';
$lang['tip_edit'] = 'edit properties';
$lang['tip_importuser'] = 'import user(s) from file';
$lang['tip_users'] = 'review users';
$lang['tip_usersedit'] = 'review/change users';
$lang['tip_view'] = 'review properties';

$lang['title_active'] = 'Active';
$lang['title_address_required'] = 'Each user must provide her/his contact-address';
$lang['title_addressable'] = 'Contactable';
$lang['title_alias'] = 'Alias';
$lang['title_attack_mitigation_span'] = 'Attack-protection interval';
$lang['title_attempts_before_ban'] = 'Login attempts before block';
$lang['title_attempts_before_verify'] = 'Login attempts before extra check';
$lang['title_context_address'] = 'Email-address used as as originator';
$lang['title_context_sender'] = 'Name of email-notice sender';
$lang['title_contextadd'] = 'Add login-context';
$lang['title_contextfull'] = 'Login-context properties';
$lang['title_contexts'] = 'Contexts';
//$lang['title_cookie_domain'] = '';
$lang['title_cookie_forget'] = 'Login/session tracking-data retention';
//$lang['title_cookie_http'] = '';
$lang['title_cookie_name'] = 'Name of http cookie which tracks logins';
//$lang['title_cookie_path'] = '';
$lang['title_cookie_remember'] = 'Login/session duration';
//$lang['title_cookie_secure'] = '';
$lang['title_email_required'] = 'The contact must be an email-address';
$lang['title_email_banlist'] = 'Prevent blacklisted email addresses';
$lang['title_forget_rescue'] = 'Enable forgotten-password rescue';
$lang['title_id'] = 'ID';
$lang['title_import'] = 'Import user-data from file';
$lang['title_lastuse'] = 'Latest login';
$lang['title_login_max_length'] = 'User-identifier maximum length';
$lang['title_login_min_length'] = 'User-identifier minimum length';
$lang['title_message_charset'] = 'Character encoding in email messages';
$lang['title_masterpass']='Pass-phrase for securing sensitive data';
$lang['title_name'] = 'Name';
$lang['title_owner'] = 'Owner';
$lang['title_password_min_length'] = 'Minimum password-length';
$lang['title_password_min_score'] = 'Password-complexity minimum score';
$lang['title_register'] = 'Registered';
$lang['title_request_key_expiration'] = 'Request-key lifetime';
$lang['title_security_level'] = 'Security level';
$lang['title_settings'] = 'Settings';
$lang['title_send_activate_message'] = 'Send account-activation emails';
$lang['title_send_reset_message'] = 'Send password-reset emails';
$lang['title_useradd'] = 'Add user';
$lang['title_userfull'] = 'User properties';
$lang['title_usersfor'] = 'Registered users for \\\'%s\\\'';

$lang['user_blocked'] = 'You are currently locked out of the system';
//$lang['user_verify_failed'] = 'Captcha text was invalid';
$lang['upload'] = 'Upload';
$lang['users'] = 'Users';

$lang['wantjs'] = 'This process would be easier if javascript were enabled in your browser.';

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
<code>#Login,Password,Passhash,Address,#Context,Update</code></p>
<h4>Other lines</h4>
<p>The data in each line must conform to the header columns, of course. Any non-compulsory field, or entire line, may be empty.<br />
If neither a Password or (previously-exported) Passhash value is provided, a default ('changethis') will be applied.<br />
Address will typically be an email address.<br />
Context may be a numeric identifier, or alias string, representing a recorded login-context.<br />
The Update field will be treated as TRUE if it contains something other than 0 or 'no' or 'NO' (no quotes, untranslated)<br />
<h3>Problems</h3>
<p>The import process will fail if:<ul>
<li>the first line field names are are not as expected</li>
<li>a compulsory-field value is not provided</li>
<li>a password is not sufficiently secure</li>
<li>an email address is malformed</li>
</ul></p>
EOS;
