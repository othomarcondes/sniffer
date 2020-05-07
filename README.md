# Packet Sniffer (WIP)

I recently started exploring Socket programming and like all other beginners, was introduced to [Wireshark](https://www.wireshark.org/). Wireshark is a software package that helps in analysing and monitoring network traffic; a packet sniffer is the basis for this analysis. This is an attempt at building a very basic packet sniffer using Python. I later plan to implement the same level of funcitonality in GoLang and if I have any sanity left, in C.

## What is a packet sniffer for?
Any conventional network carries data in packets that are manufactured by one server (or computer) and sent out to one or more servers on the same network. For security reasons or to just be nosy, one might want to analyse the traffic that such a network produces. This means keeping track of the packets that travel across the network by "sniffing" or detecting them and decoding their content. Et voila, a packet sniffer.

To understand the code, you might want to develop a basic understanding of [sockets](https://medium.com/swlh/understanding-socket-connections-in-computer-networking-bac304812b5c) and the [structure of an IPv4 network packet](https://en.wikipedia.org/wiki/IPv4#Packet_structure). The program is made using the Python [Socket API](https://docs.python.org/3/library/socket.html).

## Tool features
The current Python implementation captures only IPv4 packets and provides the following info:
- Destination and Source MAC address
- Ethernet Protocol 
- Protocol used (e.g. 6 means its a TCP packet)
- TTL (Time-to-Live)
- Header length

## To run:
In its current state, the program requires a Linux machine and Python3 installed. A packet sniffer shouldn't technically be OS-specific but that work is still in progress. Also, you'll need to use root privileges to run. The command I'm using:
```bash
sudo python3 sniffer_2.py
```