#!/usr/bin/env ruby

require 'rubygems'
require 'rex/core'
require 'rex/socket'
require 'rex/text'

begin
	sock = Rex::Socket::Udp.create( 'PeerHost' => "localhost",
					'PeerPort' =>  65535,
					'LocalPort' => 65535,
					)
	sock.write(Rex::Text.pattern_create(10))
rescue => e
	puts "[!] #{e.to_s}"
end

