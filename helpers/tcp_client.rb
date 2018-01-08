#!/usr/bin/env ruby -I/home/mc/msf/lib
require 'rex'
begin
	sock = Rex::Socket::Tcp.create( 'PeerHost'  => "localhost", 
			       		'PeerPort'  => 65535,
			      )

	sock.write(Rex::Text.pattern_create(10))
#	res = sock.get_once()
#	puts Rex::Text.to_hex_dump(res)
rescue => e
	puts "[!] #{e}"
	exit
end
