"""
  The real stuff. 
"""

import socket,sys,struct

def main():
	# Cria um socket de rede utilizando funções nativas do python
	try:
		sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	except socket.error:
		print('Socket could not be created.')
		sys.exit(1)

	def get_mac_address(bytesString):
		bytesString = map('{:02x}'.format, bytesString)
		destination_mac = ':'.join(bytesString).upper()
		return destination_mac

	def get_constants(prefix):
		# Cria um dicionário mapeando as constantes do módulo de socket para seus nomes
		return dict( (getattr(socket, n), n)
					for n in dir(socket)
					if n.startswith(prefix)
					)

	protocols = get_constants('IPPROTO_')

	with open("result.txt", "w") as file:
		file.write("\n")

	# Enquanto o loop é executado infinitamente para capturar qualquer pacote de entrada
	while True:

		# Escuta na porta 65565
		raw_data, address = sock.recvfrom(65565)
		destination_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw_data[:14])

		# Parâmetros do pacote
		destination_mac = get_mac_address(destination_mac)
		src_mac = get_mac_address(src_mac)
		eth_prot = socket.htons(ethernet_proto)
		# try:
		# 	ethernet_proto = protocols[ethernet_proto]
		# except:
		# 	ethernet_proto = "None"
		data = raw_data[14:]

		print('\nEthernet frame:')
		print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, src_mac, eth_prot))
		# Cria o arquivo result.txt
		with open("result.txt", "a") as file:
			file.write('\nEthernet frame:')
			file.write('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, src_mac, eth_prot))

		
		ethernet_proto = hex(ethernet_proto)
		# Captura pacotes IPv4
		if (ethernet_proto == '0x800'):
			version_header_len = data[0]
			version = version_header_len >> 4
			header_len = (version_header_len & 15) * 4
			ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
			# Captura o nome do protocolo
			try:
				protocolo = protocols[proto]
				protocolo = proto.split("_")[1] + " Protocol"
			except:
				protocolo = "None Specified"

			src = '.'.join(map(str,src)) 
			target = '.'.join(map(str,target)) 

			print('IPv4 packet:')
			print('\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
			print('\t{}, Source: {}, Target: {}'.format(protocolo,src,target))

			# Salva o resultado no arquivo result.txt
			with open("result.txt", "a") as file:
				file.write('\nIPv4 packet:')
				file.write('\n\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
				file.write(',{}, Source: {}, Target: {}\n'.format(protocolo,src,target))

			#TCP
			if proto == 6:
				src_port, dest_port, seq, ack, offset, flag_cwr, flag_ece, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, checksum, urgent = tcp(data)
				print('\tTCP Segment:')
				print('\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
				print('\t\tSequence Number: {}'.format(seq))
				print('\t\tAcknowledgment Number: {}'.format(ack))
				print('\t\tOffset: {}, CWR: {}, ECE: {}'.format(offset,flag_cwr, flag_ece))
				print('\t\tURG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
				print('\t\tRST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
				print('\tWindow: {}, Checksum: {}, Urgent:{}'.format(window, checksum, urgent))

				with open("result.txt", "a") as file:
					file.write('\n\tTCP Segment:')
					file.write('\n\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
					file.write('\n\t\tSequence Number: {}'.format(seq))
					file.write('\n\t\tAcknowledgment Number: {}'.format(ack))
					file.write('\n\t\tOffset: {}, CWR: {}, ECE: {}'.format(offset,flag_cwr, flag_ece))
					file.write('\n\t\tURG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
					file.write('\n\t\tRST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
					file.write('\n\tWindow: {}, Checksum: {}, Urgent:{}'.format(window, checksum, urgent))

		if(ethernet_proto == '0x86dd'):

			# Captura pacotes IPv6
			data = raw_data[14:]
			version_header_len = data[0]
			version = (version_header_len & 0xf0) >> 4
			header_len = version_header_len & 0x0f
			ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
			# Captura o nome do protocolo
			try:
				protocolo = protocols[proto]
				protocolo = protocolo.split("_")[1] + " Protocol"
			except:
				protocolo = "None Specified"
			src = '.'.join(map(str,src)) 
			numbers = list(map(int, src.split('.')))
			source = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)
			target = '.'.join(map(str,target)) 
			numbers = list(map(int, target.split('.')))
			target = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)
			print('IPv6 packet:')
			print('\tVersion: {}, Header length: {}, TTL: {}'.format(version, header_len, ttl))
			print('\t{}, Source: {}, Target: {}'.format(protocolo, source, target))

			# Salva o resultado no arquivo result.txt
			with open("result.txt", "a") as file:
				file.write('\nIPv6 packet:')
				file.write('\n\tVersion: {}, Header length: {}, TTL: {}'.format(version, header_len, ttl))
				file.write(',{}, Source: {}, Target: {}'.format(proto, source, target))

			#TCP
			if proto == 6:
				src_port, dest_port, seq, ack, offset, flag_cwr, flag_ece, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, checksum, urgent = tcp(data[:20])
				print('\tTCP Segment:')
				print('\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
				print('\t\tSequence Number: {}'.format(seq))
				print('\t\tAcknowledgment Number: {}'.format(ack))
				print('\t\tOffset: {}, CWR: {}, ECE: {}'.format(offset,flag_cwr, flag_ece))
				print('\t\tURG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
				print('\t\tRST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
				print('\tWindow: {}, Checksum: {}, Urgent:{}'.format(window, checksum, urgent))

				with open("result.txt", "a") as file:
					file.write('\n\tTCP Segment:')
					file.write('\n\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
					file.write('\n\t\tSequence Number: {}'.format(seq))
					file.write('\n\t\tAcknowledgment Number: {}'.format(ack))
					file.write('\n\t\tOffset: {}, CWR: {}, ECE: {}'.format(offset,flag_cwr, flag_ece))
					file.write('\n\t\tURG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
					file.write('\n\t\tRST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
					file.write('\n\tWindow: {}, Checksum: {}, Urgent:{}'.format(window, checksum, urgent))

		print()
		with open("result.txt", "a") as file:
			file.write("\n")

def tcp(data):
	(src_port, dest_port, sequence, ack, offset_reserved_flags, window, checksum, urgent) = struct.unpack('! H H L L H H H H', data[:20])
	offset = (offset_reserved_flags >> 12) * 4
	flag_cwr = (offset_reserved_flags & 128) >> 7
	flag_ece = (offset_reserved_flags & 64) >> 6
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	return src_port, dest_port, sequence, ack, offset, flag_cwr, flag_ece, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, checksum, urgent

if __name__ == '__main__':
    main()