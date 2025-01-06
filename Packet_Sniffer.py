from scapy.all import *
interface='eth0'
probereq=[]

def Sniff_proves(p):
    if p.haslayer(Dot1lprobereq):
        netname=p.getlayer(Dot1lprobereq).info
        if netname not in probereq:
            probereq.append(netname)
            print("Detected new network probe:"+ netname)

sniff(iface=interface,prn=Sniff_proves)