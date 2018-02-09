#!/usr/bin/env ruby

require 'rubygems'
require 'rex/core'
require 'rex/socket'
require 'rex/text'

sock = Rex::Socket::Tcp.create('PeerHost'  => "www.google.com", 'PeerPort'  => 443, 'SSL' => true)
sock.write("GET / HTTP/1.0\r\n\r\n")
res = sock.get_once()
puts Rex::Text.to_hex_dump(res)
