#!/usr/bin/env ruby
require 'rex'

s = Rex::Socket::TcpServer.create( 'LocalHost' => "0.0.0.0",
                                   'LocalPort' => "2145",
                                   'SSL' => false,
                                 )

client = s.accept
puts "[*] GOT Connection from: #{client.peerhost}:#{client.peerport}"
x = client.recvmsg()
puts Rex::Text.to_hex_dump(x[0])
client.write("WTFSTFU" + "\r\n")
