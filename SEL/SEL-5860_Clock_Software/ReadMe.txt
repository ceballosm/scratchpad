SEL-5860 Clock Software
  Copyright (C) 2018 
  Schweitzer Engineering Laboratories, Inc.
  All Rights Reserved
-------------------------------------------------------------------------------
Contents:
-------------------------------------------------------------------------------
1. Installing and Uninstalling SEL-5860 Clock Software
 
2. General Information

3. Version History

4. Known Issues

5. Contact SEL


-------------------------------------------------------------------------------
1.	Installing and Uninstalling SEL-5860 Clock Software
-------------------------------------------------------------------------------

System Requirements
-----------------------------
- Microsoft Windows XP 32-bit Edition SP3 or later, 64-bit Edition SP2 or later 
- Windows Server 2003 (32-bit and 64-bit)
- Windows Server 2008 (64-bit) R2
- Windows Server 2012 (64-bit)
- Windows 7 (32-bit and 64-bit)
- Windows 8 (32-bit and 64-bit)
- Microsoft .NET 4.0 or later 
- Administrative privileges required for installation
- 1 GHz or faster processor
- 256 MB RAM
- 200 MB temporary hard disk space for installation
- 60 MB permanent hard disk space
- VGA 800 x 600 pixels or greater resolution monitor
- Keyboard and mouse or other pointing device
- Serial connection for communication with SEL Satellite-Synchronized Clock 

Install:
Run the Setup executable downloaded from the SEL website.  
Previous versions of the SEL-5860 Clock Software are uninstalled 
automatically during the new installation.  

Uninstall:
From the Control Panel, select Add/Remove Programs, 
select SEL-5860 Clock Software, and click the Remove button. 

-------------------------------------------------------------------------------
2.	General Information
-------------------------------------------------------------------------------

The SEL-5860 Clock Software enables a Windows PC to use an SEL Satellite-Synchronized 
Clock (SEL-2401 or SEL-2407) as its time source.  The PC connects to the clock via a serial port,
and the SEL-5860 software configures the clock as the time provider for the PC's Windows W32 Time 
Service.   The PC will send "UTC" commands to the clock and the clock returns UTC time.  

-------------------------------------------------------------------------------
3.	Version History
-------------------------------------------------------------------------------
Version 2.0.1.0 ???DID THEY TELL YOU???
        - Fix for unquoted service path enumeration vulnerability.
Version 2.0.0.11
	- Initial release using the Time Provider scheme.
	
-------------------------------------------------------------------------------
4.	Known Issues
-------------------------------------------------------------------------------

By default on Windows 7 and later, the only notification area icons that will 
be visible are some system icons.  The SEL-5860 Configuration Application 
notification area icon will be displayed in the notification area overflow 
unless promoted to the notification area by the user.

To always show all icons on the taskbar:
1.  Right-click an empty area on the taskbar, and then click Properties.
2.  Under Notification area, click Customize.
3.  Select the Always show all icons and notifications on the taskbar check 
    box, and then click OK.

-------------------------------------------------------------------------------
5.	Contact SEL
-------------------------------------------------------------------------------
        
        Schweitzer Engineering Laboratories, Inc.
        2350 NE Hopkins Court
        Pullman, WA 99163-5603 U.S.A.
        Tel: +1.509.332.1890
        Fax: +1.509.332.7990
        Internet: www.selinc.com
        Email: info@selinc.com
