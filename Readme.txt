================================================================================
IeSwitchSsl 0.3.1
Copyright ©2008 Liam Kirton <liam@int3.ws>

15th March 2008
http://int3.ws/
================================================================================

Overview:
---------

IeSwitchSsl is a simple toolbar for Internet Explorer that allows for rapidly
switching between supported SSL protocols and cipher strengths. It also provides
the ability to pick specifically supported algorithms and to disable SSL
certificate verification (particularly useful when using MITM proxies, such
as WwwProxy, Paros or Burp).

Requirements:
-------------

Visual C++ 2008 runtime libraries are required. If these are not installed,
they are available from:

http://www.microsoft.com/downloads/details.aspx?familyid=200b2fd9-ae1a-4a14-984d-389c36f85647&displaylang=en

WARNING:
--------

IeSwitchSsl is an experimental tool, and achieves its results via methods that
are totally unsupported by Microsoft. Use of this tool is at your own risk! In
particular, when IeSwitchSsl is actively engaged in SSL manipulation (i.e. the
‘On’ button has been pressed), other security providers (e.g. NTLM authentication)
will not function correctly. This can be fixed by closing and restarting Internet
Explorer.

Install:
--------

> Install.bat

OR

> regsvr32 IeSwitchSsl.dll

Uninstall:
----------

> regsvr32 /u IeSwitchSsl.dll

Usage:
------

Enable and position the toolbar within Internet Explorer.

Select desired algorithms and cipher strengths from the relevant drop-down
lists.

================================================================================