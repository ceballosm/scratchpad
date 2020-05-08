#!/usr/bin/env ruby
# Trading Technologies messaging daemon.
require 'rex'

host = ARGV[0]

def usage
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

begin
sock = Rex::Socket::Tcp.create('PeerHost'  => host, 
                               'PeerPort'  => 10400)

req = [0x0000001b].pack('V') + "TTMNG_PROTOCOL_VERSION" + "\x00\x32\x2E\x30\x00"
sock.write(req)
res = sock.get_once()
#puts Rex::Text.to_hex_dump(res)
select(nil,nil,nil,0.5)
res = sock.get_once()
puts Rex::Text.to_hex_dump(res)
rescue => e
puts "[!] #{e.to_s}"
end
