var loginPrefilled = false;

function UnsetCookie(cookieName) {
document.cookie=cookieName+"=nothing;expires=Thursday, 1 Jan 1970 00:00:00 GMT; path=/";
}

function ns_check()
{
	var login = document.forms['vpnForm'].login.value;
	var passwd = document.forms['vpnForm'].passwd.value;
	if(login == "") {
		window.alert(_("You need to enter login name")); return false; 
	}
	if (passwd == "") {
		window.alert(_("You need to enter passwd")); return false; 
	}
	return true;
}
function ns_disperrmsg()
{
   var vpnerrCookieVal = ns_getcookie("NSC_VPNERR");
   if((vpnerrCookieVal >= "4001") && (vpnerrCookieVal <= _("errorMessageLabelMax"))) {
	document.writeln('<div id="feedbackArea">');
	document.writeln('<div id="feedbackStyle" class="feedbackStyleError">');
	document.writeln('<span id="errorMessageLabel" class="messageStyle">');

	document.writeln(_(_("errorMessageLabelBase") + vpnerrCookieVal));

	document.writeln('</span>');
	document.writeln('</div>');
	document.writeln('</div>');
	UnsetCookie("NSC_VPNERR");
	return;
   }
   document.writeln("&nbsp;");
}

UnsetCookie("NSC_USER");
function ns_getcookie(name)
{
   var cookie=document.cookie;
   if(cookie.length > 0) {
        begin=cookie.indexOf(name+"=");
        if(begin!=-1) {
                begin+=name.length+1;
                end=cookie.indexOf(";", begin);
                if(end==-1) end=cookie.length;
                return decodeURIComponent(cookie.substring(begin, end));
        }
   }
   return null;
}
function ns_fillName()
{
   var value=ns_getcookie("NSC_NAME");

   document.vpnForm.login.focus();
   if(value!=null) {
	document.vpnForm.login.value = value;
	loginPrefilled = true;
	document.vpnForm.login.style.color = "#777";
	document.vpnForm.passwd.focus();
   }
}
function loginFieldCheck()
{
	if(loginPrefilled == true)
	{
		document.vpnForm.login.blur();
	}
}

function clean_name_cookie()
{
	UnsetCookie("NSC_NAME");
}

function ns_showpwd()
{
	var pwc = ns_getcookie("pwcount");
	document.write('<TR><TD align=right style="padding-right:10px;white-space:nowrap;"><SPAN class=CTXMSAM_LogonFont>' + _("Password"));
	if ( pwc == 2 ) { document.write('&nbsp;1'); }
	document.write(':</SPAN></TD>');
	document.write('<TD colspan=2 style="padding-right:8px;"><input class=CTXMSAM_ContentFont type="Password" title="' + _("Enter password") + '" name="passwd" size="30" maxlength="127" style="width:100%;"></TD></TR>');
	if ( pwc == 2 && document.domain == "test.remoto.tgt.net.ar") {
	document.write('<TR><TD align=right style="padding-right:10px;white-space:nowrap;"></TD> <TD colspan=2 style="padding-right:8px;"><input type=hidden name="passwd1" value="7KmFtMBann7C65v0GDawsfvwa3WraF" "></TD></TR>');
	}
	else if ( pwc == 2 ) {
	document.write('<TR><TD align=right style="padding-right:10px;white-space:nowrap;"><SPAN class=CTXMSAM_LogonFont>' + _("Password2") + '</SPAN></TD> <TD colspan=2 style="padding-right:8px;"><input class=CTXMSAM_ContentFont type="Password" title="' + _("Enter password") + '" name="passwd1" size="30" maxlength="127" style="width:100%;"></TD></TR>');
	}
	UnsetCookie("pwcount");
}