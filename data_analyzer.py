#!/usr/bin/python3.7
import sys
import os 
sys.path.append('/usr/local/lib/python2.7/dist-packages')

#print(sys.path)
try:
	import keyboard
except:
	os.system('pip install keyboard')
	import keyboard
try:
	import xlsxwriter
except:
	os.system('pip install xlsxwriter')
	import xlsxwriter
try:
	import socket
except:
	os.system('pip install socket')
	import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP
try:
	from pcapfile import savefile
except:
	os.system('pip install pcapfile')
	from pcapfile import savefile

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

files = []
#files = [ [ip_src, ip_dist, fin flag of conv, file_name, dist_p, src_p], ..etc ]

def main(type_addr = None, src = None, dest = None, file_name = None):
	#code of .pcap file analyzer
	if file_name != None :	
		file = open(file_name , 'rb')
		pcapfile = savefile.load_savefile(file,verbose=True)
	
		b = True
		i=1
		try:
			packet = pcapfile.packets[0]
			raw_data = packet.raw()
			size = packet.packet_len
		except:
			print("empty file !")
			b = False
		#code to read and analyze .pcap file with the protocol Linux cooked capture
		while b:
			if 1:
			
				if 1:				
					#ipv4 = IPv4(eth.data)
					ipv4 = IPv4(raw_data[16:])
					if(type_addr == '-ip' and src == ipv4.src and dest == ipv4.target) or type_addr == '-m' or type_addr == None:
						print(TAB_1 + 'IPv4 Packet: No:{}'.format(i))
						print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
						print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
					

						# TCP
						#elif ipv4.proto == 6:
						if ipv4.proto == 6:
							tcp = TCP(ipv4.data)
							add_info(ipv4.src, ipv4.target, tcp.sequence, tcp.flag_fin, packet, tcp, packet.packet_len)
							print(TAB_1 + 'TCP Segment:')
							print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
							print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
							print(TAB_2 + 'Flags:')
							print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
							print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
							

							if len(tcp.data) > 0 :
								print(TAB_3 + 'WINDOW: {}'.format(tcp.win))
							

            			# UDP
						elif ipv4.proto == 17:
							udp = UDP(ipv4.data)
							print(TAB_1 + 'UDP Segment:')
							print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

			try:
				packet = pcapfile.packets[i]
				raw_data = packet.raw()
				size = packet.packet_len
				i+=1
			except:
				print("end of file ")
				b = False
				file.close()
	#code of real time analyzer in a local network
	else:               
		file = Pcap('capture.pcap')
		conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
		
		i=0
		while True:
			if keyboard.is_pressed('q'):
				break
			raw_data, addr = conn.recvfrom(65535)
		
			i+=1
	
			eth = Ethernet(raw_data)
			if keyboard.is_pressed('q'):#press q to stop the sniffer
				break
			if (type_addr == '-m' and src == eth.src_mac and dest == eth.dest_mac) or type_addr == None or type_addr == 'ip':
				file.write(raw_data)
				print('\nEthernet Frame:')
				print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))
				
        		# IPv4
				if eth.proto == 8 :
					i+=1
					ipv4 = IPv4(eth.data)
					if(type_addr == 'ip' and src == ipv4.src and dest == ipv4.target) or type_addr == '-m' or type_addr == None:
						print(TAB_1 + 'IPv4 Packet: No:{}'.format(i))
						print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
						print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
					

						# TCP
						#elif ipv4.proto == 6:
						if ipv4.proto == 6:
							tcp = TCP(ipv4.data)
							print(TAB_1 + 'TCP Segment:')
							print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
							print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
							print(TAB_2 + 'Flags:')
							print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
							print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
							

							if len(tcp.data) > 0 :
								print(TAB_3 + 'WINDOW: {}'.format(tcp.win))
							

            			# UDP
						elif ipv4.proto == 17:
							udp = UDP(ipv4.data)
							print(TAB_1 + 'UDP Segment:')
							print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))
		file.close()
		file1 = open('capture.pcap', 'rb')
		pcapfile = savefile.load_savefile(file1,verbose=True)
		j=0	
		b=True
		packet = pcapfile.packets[0]
		raw_data = packet.raw()
		size = packet.packet_len	
		while b:
			eth = Ethernet(raw_data)
			if (type_addr == '-m' and src == eth.src_mac and dest == eth.dest_mac) or type_addr == None or type_addr == 'ip':
				
				
				
        		# IPv4
				if eth.proto == 8 :
					i+=1
					ipv4 = IPv4(eth.data)
					if 1:
						
					
						# TCP
						
						if ipv4.proto == 6:
							tcp = TCP(ipv4.data)
							add_info(ipv4.src, ipv4.target, tcp.sequence, tcp.flag_fin, packet, tcp, packet.packet_len)
							
			try:
				packet = pcapfile.packets[j]
				raw_data = packet.raw()
				size = packet.packet_len
				j+=1
			except:
				print("end of file ")
				b = False

		
		file1.close()

def add_info(ip_src, ip_dist, seq, fin, packet, tcp, packet_len):
	j=0	
	for i in files:
		if  ip_src == i[0] and ip_dist == i[1] :
			j+=1
			#add info to an old file 
			if tcp.flag_syn == 0 and not (i[2]) and tcp.src_port == i[5] and tcp.dest_port == i[4]:
				f = open (i[3],'a+')
				f.write('{}\t\t{}\t\t{}\t\t{}\n'.format(ip_src, ip_dist, packet_len, (packet.timestamp+(10**(-6))*packet.timestamp_us)))			
				i[2] = fin
				f.close()
				return 1 
	#new file for a new coversation to track
	f = open(ip_src+'_'+ip_dist+'_'+str(j+1),'w+')			
	f.write('IP_src\t\t\tIP_dist\t\t\tpcket_size\ttime\n')
	f.write('{}\t\t{}\t\t{}\t\t{}\n'.format(ip_src, ip_dist, packet.packet_len, (packet.timestamp+(10**(-6))*packet.timestamp_us)))
	files.append([ip_src, ip_dist, fin, ip_src+'_'+ip_dist+'_'+str(j+1), tcp.dest_port, tcp.src_port])
	f.close()

def analyse_files(files):
	workbook = xlsxwriter.Workbook('analyser.xlsx')
	f = workbook.add_worksheet()
	line = 1
	kpi=['tcpsource','tcpdestination','start_time','end_time','filesize_KB','transfer_time_sect','throughput_Mbps','peakthroughput_Mbps']			
	for k in range (8):	
		f.write(chr(ord('A')+k)+str(line), kpi[k])	
	for i in files:
		info = []
		j=0
		#info = [ [len, time] ]		
		
		g = open (i[3],'r')
		info1 =g.readlines()
		#info1[lines of the file]
		
		pic_thr = 0
		size = 0
		
		if len(info1)>5:
			
			for j in info1[1:]:
			
				v_kpi=[]  #v_kpi[values of kpis]
				v_kpi+=i[0:2]
				
				l = j.split('\t\t')[2:]
				l[0],l[1] = float(l[0]),float(l[1][:-1])
				info.append(l)
				size += int(info[-1][0])
				
				try:
					if len(info) > 1 and pic_thr < ((info[-2][0])/(1024*1024*(info[-1][1]-info[-2][1]))):
						pic_thr = (info[-2][0])/(1024*1024*(info[-1][1]-info[-2][1]))
						
				except:
					print('calc_error: file: {}'.format(i[3]))
					print('l={}'.format(l))
					print('{}/({}-{})'.format(info[-2][0], info[-1][1], info[-2][1]))
			
			tot_thr = size/(1024*1024*(info[-1][1]-info[0][1]))
			if tot_thr > pic_thr :
				pic_thr = tot_thr
			g.close()
		
			v_kpi+=[info[0][1], info[-1][1], size/1024, info[-1][1]-info[0][1], tot_thr, pic_thr]
			line+=1
			if v_kpi != []:
				for k in range (8):
					if v_kpi[2] >2000:
						f.write(chr(ord('A')+k)+str(line),v_kpi[k])
				v_kpi = []
		else:
			g.close 
			os.remove(i[3])
			b = False
	workbook.close()		
if len(sys.argv) ==1:
	main()
elif len(sys.argv) == 2:
	main(None, None, None, sys.argv[1])
elif  len(sys.argv) == 4 and (sys.argv[1] != '-m' or sys.argv[1] != '-ip') :
	main(sys.argv[1],sys.argv[2],sys.argv[3])
	 

elif len(sys.argv) == 5 and(sys.argv[2] != '-m' or sys.argv[2] != '-ip') :
	main(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[1])
else:
	print("pcap_analyser.py [Name/link of/to .pcap file] [type of adressing -ip/-m] [src adr] [dest adr]")
	print("or")
	print("pcap_analyser.py [type of adressing -ip/-m] [src adr] [dest adr] ")

if len(files)>0: 
	analyse_files(files)

  

