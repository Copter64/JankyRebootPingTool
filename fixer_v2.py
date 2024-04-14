import subprocess
import time
import telnetlib
import datetime
import time
import re
import sys

IP_ADDRESS = "10.1.60.100"  # Replace with the IP address you want to ping
MAC_ADDRESS = "78:8a:20:5c:16:9a" #Replace with the WAP's mac address
PING_INTERVAL = 30  # Time in seconds between each ping attempt
MAX_FAILED_PINGS = 3  # Number of failed pings before resetting the switch port
MAX_FAILURES_BEFORE_ARP = 2 #Number of times the switch will reboot the AP switchport before checking if the IP changed
BOUNCE_FAILURES = 0 #used to store how many times the port bounce failed

# SSH connection information for the ExtremeXOS switch
ACCESS_SWITCH_IP = "10.1.70.2" #Used to select the switch where the WAP is connected
CORE_SWITCH_IP = "10.1.70.1" #Used to lookup the arp table to pull IP from a given MAC address
WAP_PORT = "8" #Port that the WAP is connected
SWITCH_USERNAME = "admin"
SWITCH_PASSWORD = ""

# datetime.datetime.now() = time.strftime("%H:%M:%S", time.localtime())

def ping(ip):
    """
    Send a ping to the specified IP address and return True if successful,
    False otherwise.
    """
    try:
        output = subprocess.check_output(f"ping {ip} -n 1 -w 1000", shell=True, timeout=5)
        if "Received = 1" in output.decode("utf-8"):
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False
    except subprocess.TimeoutExpired:
        return False


def port_bounce(ip,user,password,switch_port):
    tn = telnetlib.Telnet(ip)
    tn.read_until(b"login: ")
    tn.write(user.encode('ascii') + b"\n")
    tn.read_until(b"password: ")
    tn.write(password.encode('ascii') + b"\n")
    disable_command = f"disable ports {switch_port}"
    tn.write(disable_command.encode('ascii') + b"\n")  # Replace with the command you want to send
    tn.read_until(b"* x430-FOH")
    print("disabling WAP port")
    time.sleep(10)
    enable_command = f"enable ports {switch_port}"
    tn.write(enable_command.encode('ascii') + b"\n")  # Replace with the command you want to send
    tn.read_until(b"* x430-FOH")
    print("enabling WAP port")
    time.sleep(30)
    tn.close()
    if ping(IP_ADDRESS):

        print(f"Device at {IP_ADDRESS} back online at {datetime.datetime.now()}")
    return

def ip_address_check(coreswitch_ip,user,password,mac_address):

    global IP_ADDRESS
    tn = telnetlib.Telnet(coreswitch_ip)
    tn.read_until(b"login: ")
    tn.write(user.encode('ascii') + b"\n")
    tn.read_until(b"password: ")
    tn.write(password.encode('ascii') + b"\n")
    tn.read_until(b"x440-ADR")
    mac_finder = f"show iparp | inc {mac_address}"
    tn.write(mac_finder.encode('ascii') + b"\n")
    IP_ADDRESS = ip_parser(str(tn.read_until(b"x440-ADR")).split())
    tn.close()
    if IP_ADDRESS:
        print(f"MAC Address: {mac_address} resolved to IP Address: {IP_ADDRESS}")
    else:
        print(f"MAC Address: {mac_address} not resolving to an IP, stopping app")
        sys.exit()
    return

def ip_parser(arp_output):
    
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for item in arp_output:
        if re.search(ip_pattern, item):
            return item
    return None

def main():
    print(f"AP Fix Application Started at {datetime.datetime.now()}...")
    global BOUNCE_FAILURES
    
    failed_pings = 0
    while True:

        if ping(IP_ADDRESS) and failed_pings > 0:
            failed_pings = 0
    
            print(f"Pings have recovered to {IP_ADDRESS} at {datetime.datetime.now()}")
        elif ping(IP_ADDRESS):
            failed_pings = 0
        else:
            print(f'Ping Failed {failed_pings + 1} times at {datetime.datetime.now()}')
            failed_pings += 1
            if failed_pings >= MAX_FAILED_PINGS:
                port_bounce(ACCESS_SWITCH_IP, SWITCH_USERNAME, SWITCH_PASSWORD,switch_port=WAP_PORT)
                BOUNCE_FAILURES += 1
                failed_pings = 0
        if BOUNCE_FAILURES >= MAX_FAILURES_BEFORE_ARP:
            BOUNCE_FAILURES = 0
            ip_address_check(coreswitch_ip=CORE_SWITCH_IP,user=SWITCH_USERNAME,password=SWITCH_PASSWORD,mac_address=MAC_ADDRESS)
            continue

        time.sleep(PING_INTERVAL)

if __name__=="__main__":
    ip_address_check(coreswitch_ip=CORE_SWITCH_IP,user=SWITCH_USERNAME,password=SWITCH_PASSWORD,mac_address=MAC_ADDRESS)
    if ping(IP_ADDRESS):
        print(f"Device at {IP_ADDRESS} is online at {datetime.datetime.now()}")
    main()


    
adding new fixer version 