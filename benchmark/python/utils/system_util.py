import os

def run_ping(ip_address):
    # Command Injection [CWE-78]
    command = "ping -c 4 " + ip_address
    os.system(command)
