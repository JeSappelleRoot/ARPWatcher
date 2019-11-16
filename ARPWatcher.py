import time
import netaddr
import requests
from scapy.all import *

def displayBanner():

    print("""
          _____  _______          __   _       _               
    /\   |  __ \|  __ \ \        / /  | |     | |              
   /  \  | |__) | |__) \ \  /\  / /_ _| |_ ___| |__   ___ _ __ 
  / /\ \ |  _  /|  ___/ \ \/  \/ / _` | __/ __| '_ \ / _ \ '__|
 / ____ \| | \ \| |      \  /\  / (_| | || (__| | | |  __/ |   
/_/    \_\_|  \_\_|       \/  \/ \__,_|\__\___|_| |_|\___|_|   
    
    """)





    return



def getOUI(mac):
# Simple function to get OUI vendor from mac address

    # Define URL of API for OUI lookup
    ouiAPI = 'https://api.macvendors.com'

    # Try/Except statement
    try:
        # Make a simple request with given mac address
        request = requests.get(f"{ouiAPI}/{mac}")

        # If API return HTTP code 404 (page not found)
        if request.status_code == 404:
            vendor = 'UNKNOW'
        # Elif API return HTTP code 200 (page found)
        elif request.status_code == 200:
            vendor = request.text 
            
        return vendor

    # Except requests module exceptions
    except requests.RequestException as error:
        print(f"[!] An error occured during looking up for {mac} : ")
        print(error)





def makeARP(ipSrc, ipDst, interface, timeout, verbose, ouiLookup):
# Simple function to make an ARP request
# "Which MAC have host with this IP ?"

    conf.checkIPaddr = False

    randomMac = RandMAC()

    ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=randomMac)
    arp = ARP(psrc=ipSrc, pdst=ipDst)

    packet = ethernet / arp

    answer, nonanswer = srp(packet, iface=interface, timeout=timeout, verbose = verbose)

    if nonanswer:
        print(f"[-] No response for {ipDst} ip address")
    elif answer:
        for snd,rcv in answer:
            macDst = rcv.sprintf(r"%Ether.src%")
            print(f"[+] MAC address found : {macDst} for {ipDst}")
            if ouiLookup:
                print(f"  - vendor : {getOUI(macDst)}")




    return



displayBanner()

target = '10.0.10.0/24'
source = '10.0.10.1'
interface = 'vboxnet0'
verbose = False
ouiLookup = True
timeout = 1
mode = 'lan'



if mode == 'ip':

    if netaddr.valid_ipv4(target):
        makeARP(source, target, interface, timeout, verbose, ouiLookup)
    else:
        print(f"[!] Print specify a valid IP address for IP mode")
        exit()

elif mode == 'lan':
    
    for ip in netaddr.IPNetwork(target).iter_hosts():
        makeARP(source, ip, interface, timeout, verbose, ouiLookup)
    



