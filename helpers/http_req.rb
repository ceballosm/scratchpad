#!/usr/bin/env ruby 

require 'rex'

sock = Rex::Proto::Http::Client.new("google.com", port = "80", context = {}, ssl = false)


req = sock.request_raw(
	{
		'uri'   => "/",
		'version' => '1.0',
		'method' => 'GET',
	})

	sock.send_request(req)
	data = sock.read_response()
	puts data.body

