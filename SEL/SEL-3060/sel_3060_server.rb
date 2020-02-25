#!/usr/bin/env ruby
# Simply provides a response to a SEL-3060 Discovery Tool request.

require 'rex'
require 'socket'

mac = "DEADCA"
ip = "\xc0\xa8\x01\x1"  # ""..to_s(16)
gw = "\x00\x00\x00\x00" # ""..to_s(16)
mask = "\xff" + "\x00" * 3

padding = "\x00" * (0x32 - mac.size - ip.size - gw.size - mask.size)
buff = "!A" + mac + ip + gw + mask + padding

sock = UDPSocket.new
sock.bind("0.0.0.0", 31113)

while true do
 data, sender = sock.recvfrom(1024)
 puts Rex::Text.to_hex_dump(data)
 port = sender[1]
 puts Rex::Text.to_hex_dump(buff) 
 sock.send(buff, 0, sender[2], "31113")
end
__END__
bp 403070

              iVar4 = recvfrom(iVar2,&buffer,0x5dc,0,local_604,&local_610);
            } while (iVar4 < 1);
            if (iVar4 == 0x38) break;
            if ((iVar4 == 0x34) && (buffer == '!')) {
              puVar5 = (undefined *)_malloc(0x38);
              *puVar5 = 0x21;
              puVar5[1] = local_5e3;
              *(undefined4 *)(puVar5 + 2) = local_5e2;
              *(undefined2 *)(puVar5 + 6) = local_5de;
              *(undefined4 *)(puVar5 + 8) = local_5dc;
              *(undefined4 *)(puVar5 + 0xc) = local_5d8;
              *(undefined4 *)(puVar5 + 0x10) = local_5d4;
              *(undefined8 *)(puVar5 + 0x16) = local_5d0;
              *(undefined8 *)(puVar5 + 0x1e) = local_5c8;
              *(undefined8 *)(puVar5 + 0x26) = local_5c0;
              *(undefined8 *)(puVar5 + 0x2e) = local_5b8;
              *(undefined2 *)(puVar5 + 0x14) = 0;
              if (puVar5[1] == 'A') {
                (*pcVar7)(param_1,0x8001,puVar5,0);
              }
              iVar2 = local_608;
              if (puVar5[1] == 'K') {
                (*pcVar7)(param_1,0x8002,puVar5,0);
                iVar2 = local_608;
              }
