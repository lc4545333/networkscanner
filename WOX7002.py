from scapy.all import *
from scapy.layers.l2 import Ether, ARP_am
import threading
import queue



class deviceMapping:
    def __init__(self):
        self.ipaddr = ('192.168.0.1')
        self.q = queue.Queue()
        self.host = []

#    def ip_part_generator(self):
#        ip_part = IP(dst = self.ipaddr)
#        return ip_part
    def set_ipaddr(self,addr):
        self.ipaddr = addr

    def ip_list_generator(self):
        ip_list = [i for i in IP(dst=self.ipaddr)]
        return ip_list

    def icmp_part_generator(self,type=8,code=0):
        icmp_part = ICMP(type = type,code = code)
        return icmp_part

    def tcp_part_generator(self,dport = 443, flags='S'):
        tcp_part = TCP(dport=dport,flags=flags)
        return tcp_part

    def udp_part_generator(self,dport = 41025):
        udp_part = UDP(dport = 41025)
        return udp_part

    def arp_scan(self):
        eth_part = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_part = ARP(pdst=self.ipaddr)
        arp_packet = eth_part/arp_part
        ans,unans = srp(arp_packet,timeout=1)
        devicesip = []
        devicesmac = []
        if ans:
            for sent, received in ans:
                devicesip.append(received.psrc)
                devicesmac.append(received.hwsrc)
        return devicesip,devicesmac


    def icmp_scan(self,ip_list,icmp_type=8,icmp_code=0):
        icmp_part = self.icmp_part_generator(icmp_type,icmp_code)
        for ip_part in ip_list:
            packet = ip_part/icmp_part
            received_packet = sr1(packet,inter =0.05,timeout=3)
            if received_packet:
                self.q.put(received_packet)

    def tcp_scan(self,ip_list,port=443,type='S'):
        tcp_part = self.tcp_part_generator(port,type)
        for ip_part in ip_list:
            packet = ip_part/tcp_part
            received_packet = sr1(packet,inter =0.05,timeout=3)
            if received_packet:
                self.q.put(received_packet)


    def udp_scan(self,ip_list,port = 41025):
        udp_part = self.udp_part_generator(port)
        for ip_part in ip_list:
            packet = ip_part/udp_part
            received_packet = sr1(packet,inter =0.05,timeout=3)
            if received_packet:
                self.q.put(received_packet)

    def run_tcp(self,port=443,type='S'):
        iplist = self.ip_list_generator()
        lenlist = len(iplist)
        threadlist = []
        tmp = []
        if lenlist>=20:
            for i in range(20):
                start_index = i*lenlist//20
                end_index = (i+1)*lenlist//20
                t = threading.Thread(target=self.tcp_scan,args=(iplist[start_index:end_index],port,type))
                threadlist.append(t)

            for thread in threadlist:
                thread.start()
            for thread in threadlist:
                thread.join()
        else:
            self.tcp_scan(iplist)

        while not self.q.empty():
            self.host.append(self.q.get())

        if len(self.host) > 0:
            for ahost in self.host:
                tmp.append(str('Find a host: The ip address is ' + ahost[IP].src))
        else:
            tmp.append('no host found')
        self.host[:] = []
        print(tmp)
        return tmp

    def run_udp(self,port = 41025):
        iplist = self.ip_list_generator()
        lenlist = len(iplist)
        threadlist = []
        tmp = []
        if lenlist>=20:
            for i in range(20):
                start_index = i*lenlist//20
                end_index = (i+1)*lenlist//20
                t = threading.Thread(target=self.udp_scan,args=(iplist[start_index:end_index],port))
                threadlist.append(t)

            for thread in threadlist:
                thread.start()
            for thread in threadlist:
                thread.join()
        else:
            self.udp_scan(iplist)

        while not self.q.empty():
            self.host.append(self.q.get())
        if len(self.host)>0:
            for ahost in self.host:
                tmp.append(str('Find a host: The ip address is '+ ahost[IP].src))
        else:
            tmp.append('no host found')
        self.host[:] =[]
        print(tmp)
        return tmp


    def run_icmp(self, icmp_type = 8,icmp_code =0):
        iplist = self.ip_list_generator()
        lenlist = len(iplist)
        threadlist = []
        tmp=[]
        if lenlist >= 20:
            for i in range(20):
                start_index = i * lenlist // 20
                end_index = (i + 1) * lenlist // 20
                t = threading.Thread(target=self.icmp_scan, args=(iplist[start_index:end_index],icmp_type,icmp_code))
                threadlist.append(t)

            for thread in threadlist:
                thread.start()
            for thread in threadlist:
                thread.join()
        else:
            self.icmp_scan(iplist)

        while not self.q.empty():
            self.host.append(self.q.get())

        if len(self.host)>0:
            for ahost in self.host:
                tmp.append(str('Find a host: The ip address is '+ ahost[IP].src))
        else:
            tmp.append('no host found')
        self.host[:] =[]
        print(tmp)
        return tmp

    def run_arp(self):
        ip,mac = self.arp_scan()
        tmp = []
        if len(ip) >0:
            for ip1,mac1 in zip(ip,mac):
                tmp.append(str('Find a host: The ip address is'+ ip1+'and its mac is:'+mac1))
        else:
            tmp.append('no host found')
        return tmp