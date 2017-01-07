<?php
#----------------------------------------------------------------------
# This file is part of CMS Made Simple module: Auther
# Copyright (C) 2017 Tom Phane <tpgww@onepost.net>
# Refer to licence and other details at the top of file Auther.module.php
# More info at http://dev.cmsmadesimple.org/projects/auther
#----------------------------------------------------------------------

$lang['admindescription'] = 'This module provides authentication functionality for other modules';
$lang['friendlyname'] = 'Authenticator';
$lang['perm_modify'] = 'Modify Authentication Data';
$lang['perm_see'] = 'Review Authentication Data';
$lang['perm_send'] = 'Send Authentication Events';
$lang['postinstall'] = 'Authenticator module installed sucessfully.<br />Be sure to set relevant permissions';
$lang['postuninstall'] = 'Authenticator module uninstalled';
$lang['really_uninstall'] = 'Are you sure you want to uninstall the Authenticator module?';

$lang['account_activated'] = 'Account activated';
$lang['account_deleted'] = 'Account deleted';
$lang['account_inactive'] = 'Account has not yet been activated';
$lang['activatekey_expired'] = 'Activation key has expired'; //NB type-specific prefix
$lang['activatekey_incorrect'] = 'Activation key is incorrect'; //NB type-specific prefix
$lang['activation_exists'] = 'An activation email has already been sent';
$lang['activationkey_invalid'] = 'Activation key is invalid';
$lang['activation_sent'] = 'Activation email has been sent';
$lang['already_activated'] = 'Account is already activated';
$lang['authority_failed'] = 'Incorrect login and/or password';

$lang['email_activation_altbody'] = 'Hello,'."\n\n".'To be able to log in you first need to activate the account by visiting the following link:'."\n".'%s/%s'."\n\n".'You then need to use the following activation key: %s'."\n\n".'If you did not sign up on %s recently then this message was sent in error, please ignore it';
$lang['email_activation_body'] = 'Hello,<br /><br />To be able to log in you first need to activate the account by clicking on the following link: <strong><a href=\'%s/%s\'>%s/%s</a></strong><br /><br />You then need to use the following activation key: <strong>%s</strong><br /><br />If you did not sign up on %s recently then this message was sent in error, please ignore it';
$lang['email_activation_subject'] = '%s - Activate account';

$lang['email_banned'] = 'The specified email address is not allowed';
$lang['email_changed'] = 'Email address changed successfully';
$lang['email_incorrect'] = 'Email address is incorrect';
$lang['email_invalid'] = 'Email address is invalid';

$lang['email_reset_altbody'] = 'Hello,'."\n\n".'To reset your password please visit the following link:'."\n".'%s/%s'."\n\n".'You then need to use the following password reset key: %s'."\n\n".'If you did not request a password reset key on %s recently then this message was sent in error, please ignore it';
$lang['email_reset_body'] = 'Hello,<br /><br />To reset your password click the following link:<br /><br /><strong><a href=\'%s/%s\'>%s/%s</a></strong><br /><br />You then need to use the following password reset key: <strong>%s</strong><br /><br />If you did not request a password reset key on %s recently then this message was sent in error, please ignore it';
$lang['email_reset_subject'] = '%s - Password reset request';

$lang['login_incorrect'] = 'Login name is not recognised';
$lang['login_notvalid'] = 'Login name is invalid';
//$lang['login_long'] = 'Login name is too long';
$lang['login_short'] = 'Login name is too short';
$lang['login_taken'] = 'Login name is already in use';

$lang['function_disabled'] = 'This function has been disabled';

$lang['logged_in'] = 'You are now logged in';
$lang['logged_out'] = 'You are now logged out';

$lang['newemail_match'] = 'New email matches previous email';
$lang['newpassword_invalid'] = 'New password must contain at least one uppercase and lowercase character, and at least one digit';
$lang['newpassword_long'] = 'New password is too long';
$lang['newpassword_match'] = 'New password is the same as the old password';
$lang['newpassword_nomatch'] = 'New passwords do not match';
$lang['newpassword_short'] = 'New password is too short';

$lang['password_changed'] = 'Password changed successfully';
$lang['password_incorrect'] = 'Password is wrong';
$lang['password_nomatch'] = 'Passwords do not match';
$lang['password_notvalid'] = 'Password is invalid';
$lang['password_reset'] = 'Password reset successfully';
$lang['password_short'] = 'Password is too short';
$lang['password_weak'] = 'Password is too weak';

$lang['register_success'] = 'Account created. Activation email sent to email';
$lang['register_success_emailmessage_suppressed'] = 'Account created';
$lang['remember_me_invalid'] = 'The remember me field is invalid';
$lang['reset_exists'] = 'A reset request already exists';
$lang['resetkey_expired'] = 'Reset key has expired'; //NB type-specific prefix
$lang['resetkey_incorrect'] = 'Reset key is incorrect'; //NB type-specific prefix
$lang['resetkey_invalid'] = 'Reset key is invalid';
$lang['reset_requested_emailmessage_suppressed'] = 'Password reset request has been created';
$lang['reset_requested'] = 'Password reset request sent to email address';

$lang['system_error'] = 'A system error has been encountered. Please try again.';

$lang['user_blocked'] = 'You are currently locked out of the system';
$lang['user_verify_failed'] = 'Captcha text was invalid';

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

$lang['help_module'] = <<<'EOS'
<h3>What does this module do?</h3>
It provides several authentication "services" for use by other parts of the website,
other modules or (after patching relevant core files) admininstrator access.
Specifically
<ul>
<li>Any number of authorisation "contexts" with individual properties</li>
<li>Several security levels</li>
<li>[De]registration of users by self and/or administrator</li>
<li>Bulk [de]registration of users by administrator</li>
<li>Login/out of users</li>
<li>User data change by self or adminstrator</li>
<li>Lost/forgotten data recovery by users</li>
<li>Optional email notices/confirmations</li>
<li>Optional 2-factor authorisation</li>
<li>Enhanced data security</li>
<li>UI objects for inclusion in page/form</li>
</ul>
<h3>How is it used?</h3>
The module includes several PHP classes which together provide a robust API for
accessing the various services as described above.
<pre></pre>
<h3>Styling</h3>
<h3>Permissions</h3>
<h4>Modify Authentication Data</h4>
<h4>Review Authentication Data</h4>
<h4>Send Authentication Events</h4>
<ul>
<h3>Events</h3>
<h4>AuthRegister</h4>
<h4>AuthDeregister</h4>
<h4>AuthLogin</h4>
<h4>AuthLoginFail</h4>
<h4>AuthLogout</h4>
<h3>Requirements</h3>
<ul>
<li>PHP 5.3+</li>
</ul>
<h3>Desirables</h3>
<h3>Support</h3>
<p>This module is provided as-is. Please read the text of the license for the full disclaimer.
Just to be clear, there's no guarantee of support. However, there are some resources available
to help you with it:</p>
<ul>
<li>for the latest version of this module, or to file a bug report, go to the
<a href="http://dev.cmsmadesimple.org/projects/auther">module's Forge page</a></li>
<li>discussion of this module may be found in the
<a href="http://forum.cmsmadesimple.org">CMS Made Simple Forums</a></li>
<li>you may have some success emailing the author directly<br />
</li>
</ul>
<h3>Copyright and license</h3>
<p>Copyright &copy; 2017 Tom Phane &lt;tpgww@onepost.net&gt;<br />
All rights reserved.</p>
<p>This module has been released under version 3 of the
<a href="http://www.gnu.org/licenses/licenses.html#AGPL">GNU Affero Public License</a>.
The module must not be used otherwise than in acccordance with that license.</p>
EOS;
