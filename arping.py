import sys
from datetime import datetime
from dcapy.all import *

#Tratamento de exceção

try:
    interface = input("\nSet interface: ")
    IPS = input("Set ip range:" )
except KetboardInterrupt:
     print("n\User aborted")
     sys.exit()

print("Scanning...")
start_time = datetime.now

conf.verb = 0

ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout=2, iface=interface, inter=0.1)
printf("\n\MAC\t\tIP\n")

#Realizando o Scan

for snd, rcv in ans:
    print(rcv.sprintf(%Ether.src% - %ARP.psrc%))
stop_time = datetime.now()
total_time = stop_time - start_time
print("\n Scan complete")
print("\nDuration: %s" %(total_time))
