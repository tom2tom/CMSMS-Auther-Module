<h3>What does this module do?</h3>
It provides several authentication "services" for use by other parts of the website,
other modules or (after patching relevant core files) admininstrator access.
Specifically
<ul>
<li>Any number of authorization "contexts" with individual properties</li>
<li>Several security levels</li>
<li>[De]registration of users by self and/or administrator</li>
<li>Bulk [de]registration of users by administrator</li>
<li>Login/out of users</li>
<li>User data change by self or administrator</li>
<li>Lost/forgotten data recovery by users</li>
<li>Optional email notices/confirmations</li>
<li>Optional 2-factor authorization</li>
<li>Enhanced data security</li>
<li>UI objects for inclusion in page/form</li>
</ul>
So this module is essentially for module-developers and the like.
<h3>How is it used?</h3>
The module includes several PHP classes which together provide a robust API for
accessing the various services as described above.<br /><br />
First, record relevant parameters in a login-context created via the module's
admin interface, and keep note of that context's identifier.<br /><br />
Into your php code, add something like the following:
<pre>
$somevar = new Auther\Setup();
list($xhtml,$js) = $somevar->GetPanel($context,$mode,$handler,$id[[,$cancellable],$token]);
</pre>
where:<br />
$context = identifier (number or alias) for the relevant recorded context<br />
$mode = mode-descriptor string, one of
<ul>
<li>'login'</li>
<li>'register'</li>
<li>'reset'</li>
<li>'change'</li>
</ul>
$handler = something to receive and process feedback after the form has been processed, one of
<ul>
<li>an array [$classname,$methodname] where $methodname is static and the method returns boolean for success</li>
<li>a string 'classname::methodname' where the method returns boolean for success</li>
<li>an array [$modulename,$actionname,$id] AND the action should be a 'doer', not a 'shower', returns HTML code</li>
<li>an array [$modulename,'method.whatever'] to be included, the code must conclude with variable $res = T/F indicating success</li>
<li>a string 'absolute-path-to-whatever.php' to be included, the code must conclude with variable $res = T/F indicating success</li>
<li>an URL like <server-root-url>/index.php?mact=<modulename>,cntnt01,<actionname>,0
 - provided the PHP curl extension is available</li>
<li><b>BUT NOT</b> a closure in a static context (PHP 5.3+) OR static closure (PHP 5.4+)</li>
</ul>
$id = module ID string, as widely used in the CMSModule class<br />
<i>(if available)</i> $token = identifier provided to $handler by a previous Get()<br />
$xhtml = displayable content (a form including inputs, buttons etc)<br />
$js = associated javascript<br /><br />
Then put the displayable content ($xhtml) and javascript ($js) into your page/template
in whatever manner is appropriate.<br /><br />
<strong>OR</strong><br /><br />
You can roll-your-own user-interface, and work with the Auth-class API directly.<br /><br />
This approach would be appropriate if authority must be checked without an actual login, for example.
<h4>API</h4>
<h3>Permissions</h3>
<h4>Modify Authentication Module Properties</h4>
<h4>Modify Authentication Contexts</h4>
<h4>Modify Authenticated Users</h4>
<h4>Review Authentication Data</h4>
<h3>Events</h3>
<h4>AuthRegister</h4>
<h4>AuthDeregister</h4>
<h4>AuthLogin</h4>
<h4>AuthLoginFail</h4>
<h4>AuthLogout</h4>
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
<h3>Requirements</h3>
<ul>
<li>PHP 5.4+</li>
<li>PHP extensions: GD, Hash, Openssl</li>
</ul>
<h3>Desirables</h3>
<h3>Styling</h3>
The following are defaults, which you might like to adapt and/or introduce where
the authentication is initialised.<br /><br />
