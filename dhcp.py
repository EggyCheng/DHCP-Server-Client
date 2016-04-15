'''
CREATE ON April 14,2016
author:EggyCheng
e-mail:eggy@csie.io
'''
import argparse, socket, struct
from uuid import getnode as get_mac
from random import randint

BUFSIZE = 65535
def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Optiony
        return packet

class DHCPOffer:
    def buildPacket(self,data):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x02'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += data[4:8]       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\xae\x82'   #assign I 174.128
        packet += b'\xc0\xa8\xae\x81'   #server IP addres  174.129
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  #Server host name not given
        packet += b'\x00' * 128 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x02'   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        #packet += b'\x3d\x06' + macb
        packet += b'\x36\x04\xc0\xa8\xae\xfe' #Option: (t=54,l=4 Server Identifier)
        packet += b'\x33\x04\x00\x00\x07\x08' #Option: (t=51,l=4 IP Address Lease Time)
        packet += b'\x03\x04\xc0\xa8\xae\x02' #Option: (t=3,l=4 Router 192.168.44.2)
        packet += b'\x01\x04\xff\xff\xff\x00' #Option: (t=1 ,l=4 Subnet Mask 255.255.255.0)
        packet += b'\x06\x04\xc0\xa8\xae\x02' #Option: (t=6 ,l=4 Domain Name Server 192.168.44.2)
        #packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        packet += b'\x00' * 26  
        return packet

class DHCPRequest:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t)
    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x03'   #Option: (t=53,l=3) DHCP Message Type = DHCP Request
        packet += b'\x32\x04\xc0\xa8\xae\x82' #Option: (t=54,l=4 server assign me the IP)
        packet += b'\x36\x04\xc0\xa8\xae\x81' #Option: (t=54,l=4 DHCP Server IP)
        packet += b'\xff'   #End Option
        return packet

class DHCPAck:
    def buildPacket(self,data):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x02'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0
        packet += data[4:8]       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\xae\x82'   #assign I 174.128
        packet += b'\xc0\xa8\xae\x81'   #server IP addres  174.129
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  #Server host name not given
        packet += b'\x00' * 128 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x05'   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        #packet += b'\x3d\x06' + macb
        packet += b'\x36\x04\xc0\xa8\xae\xfe' #Option: (t=54,l=4 Server Identifier)
        packet += b'\x33\x04\x00\x00\x07\x08' #Option: (t=51,l=4 IP Address Lease Time)
        packet += b'\x03\x04\xc0\xa8\xae\x02' #Option: (t=3,l=4 Router 192.168.44.2)
        packet += b'\x01\x04\xff\xff\xff\x00' #Option: (t=1 ,l=4 Subnet Mask 255.255.255.0)
        packet += b'\x06\x04\xc0\xa8\xae\x02' #Option: (t=6 ,l=4 Domain Name Server 192.168.44.2)
        #packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet




def server():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.bind(('0.0.0.0', 67))
	print('Listening for datagrams at {}'.format(sock.getsockname()))
	while True:
		data, address = sock.recvfrom(BUFSIZE)
		#print ('The client at {} says: {!r}'.format(address, data))
		print ("Receving DHCP Discovery from " + address[0])
		offerPacket = DHCPOffer()
		sock.sendto(offerPacket.buildPacket(data), ('255.255.255.255', 68))
		RquestData, address = sock.recvfrom(BUFSIZE)
		#print ('The client at {} says: {!r}'.format(address, RquestData))
		print ("Receving DHCP Request from " + address[0])
		ackPacket = DHCPAck()
		sock.sendto(ackPacket.buildPacket(RquestData), ('255.255.255.255', 68))
			
def client():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.bind(('0.0.0.0', 68))
	discoverPacket = DHCPDiscover()
	sock.sendto(discoverPacket.buildPacket(), ('255.255.255.255', 67))
	while True:
		data, address = sock.recvfrom(BUFSIZE)
		if address[0] == "192.168.174.129":
			break
	requestPacket = DHCPRequest()
	sock.sendto(requestPacket.buildPacket(), ('255.255.255.255', 67))
	while True:
		ackdata, address = sock.recvfrom(BUFSIZE)
		if address[0] == "192.168.174.129":
			break
	offerIP = '.'.join(map(lambda x:str(x), ackdata[16:20]))
	nextServerIP = '.'.join(map(lambda x:str(x), ackdata[20:24]))
	print ("I found the DHCP IP address is:" + nextServerIP)
	print ("I have been assigned IP:" + offerIP)


if __name__ == '__main__':
	choices = {'client':client, 'server': server}
	parser = argparse.ArgumentParser(description='Send, receive UDP broadcast')
	parser.add_argument('role', choices=choices, help='which role to take')
	args = parser.parse_args()
	function = choices[args.role]
	function()
