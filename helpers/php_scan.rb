#!/usr/bin/env ruby
# catches some stuff. but you will need to validate.

api = ["shell","exec","eval","passthru","shell_exec","system"]

lines = []

file = ARGV[0]

def usage
 puts "[*] Scan a file for api's"
 puts "[*] #{$0} <file>"
 exit
end

usage if ARGV.size < 1

File.open(file,"rb").each_line do |x|
lines << x
end

lines.each do |x|
 if x.match(api[0])
  puts "#{x.strip}"
 elsif x.match(api[1])
  puts "#{x.strip}"
 elsif x.match(api[2])
  puts "#{x.strip}"
 elsif x.match(api[3])
  puts "#{x.strip}"
 elsif x.match(api[4])
  puts "#{x.strip}"
 elsif x.match(api[5])
  puts "#{x.strip}"
end
end
