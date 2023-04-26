import subprocess
import time
import paramiko
import telnetlib


IP_ADDRESS = "10.1.60.101"  # Replace with the IP address you want to ping
PING_INTERVAL = 30  # Time in seconds between each ping attempt
MAX_FAILED_PINGS = 5  # Number of failed pings before resetting the switch port

# SSH connection information for the ExtremeXOS switch
SWITCH_IP = "10.1.70.2"
SWITCH_USERNAME = "admin"
SWITCH_PASSWORD = ""


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


def port_bounce(ip,user,password):
    tn = telnetlib.Telnet(ip)
    tn.read_until(b"login: ")
    tn.write(user.encode('ascii') + b"\n")
    tn.read_until(b"password: ")
    tn.write(password.encode('ascii') + b"\n")
    tn.write(b"disable ports 8\n")  # Replace with the command you want to send
    tn.read_until(b"* x430-FOH")
    print("disabling WAP port")
    time.sleep(10)
    tn.write(b"enable ports 8\n")  # Replace with the command you want to send
    tn.read_until(b"* x430-FOH")
    print("enabling WAP port")
    time.sleep(60)
    tn.close()
    return

def main():
    print("AP Fix Application Running...")
    failed_pings = 0
    while True:
        if ping(IP_ADDRESS):
            failed_pings = 0
        else:
            print(f'Ping Failed {failed_pings + 1} times')
            failed_pings += 1
            if failed_pings >= MAX_FAILED_PINGS:
                port_bounce(SWITCH_IP, SWITCH_USERNAME, SWITCH_PASSWORD)
                failed_pings = 0
        time.sleep(PING_INTERVAL)

if __name__=="__main__":
    main()
