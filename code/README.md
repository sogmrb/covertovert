# Covert Storage Channel that exploits Packet Bursting using NTP [Code: CSC-PB-NTP]

Sogol Mehrabi 2547321
Yiğitcan Özcan 2521847
Group 30
https://github.com/sogmrb/covertovert

Our project implements a covert channel that uses bursts of NTP packets to encode and transmit a binary message in a surreptitious manner. Covert channels take advantage of the unconsidered paths of legitimate protocols in order to transfer data. This channel could be used for research in security, ethical hacking, or advanced communication systems, with further enhancements.

imports:
    The time module is used for measuring time intervals (e.g., delays between sending packets) and introducing pauses (time.sleep()). We import the base class CovertChannelBase, which contains shared methods like send and logging functions. The MyCovertChannel class inherits from this base class to reuse its functionality.
    
    NTP: Represents an NTP (Network Time Protocol) packet.
    IP: Represents the IP layer of a network packet.
    UDP: Represents the UDP layer of a network packet.
    sniff: A Scapy function to capture packets from the network.

calculate_delay(self, dest):
    Firstly, we initialize an empty list to store the delays for each packet. Then, in a for loop we measure the delay for 10 packets. Inside of the the loop, we create a network packet with three layers:
        IP Layer: Specifies the destination (dst=dest).
        UDP Layer: Specifies the transport layer (User Datagram Protocol).
        NTP Layer: Specifies the application layer (NTP).
    After that, we record the current time before sending the packet and send the packet using the send method from the parent class. We calculate the time taken to send the packet and append it to the delays list. Lastly, we compute the average delay and return it.

send(self, log_file_name, zero_packet_count, one_packet_count):
    We generate a random binary message and log it to the specified file and calculate the idle time as three times the average delay to the destination receiver. Then, we iterate through each bit in the binary message, while initializing an empty list to store the packets for the current burst; in order to determine the number of packets to send based on the value of the bit. After that, we define a loop to create the required number of packets for the burst and create a packet destined for receiver then we add the packet to the list for the current burst. Our function waits for the idle time before sending the burst to separate it from the previous one and iterates through the list of packets in the burst. At final step, it sends each packet using the parent class method.

receive(self, log_file_name, zero_packet_count, one_packet_count):
    At the start, we initialized the values to be used, calculated idle_time which is dependent on delay of sender. It sniffs network traffic by using "sniff" with these parameters:
        prn=sniff_handler: Specifies the function to call for each captured packet.
        iface="eth0": Captures packets on the eth0 interface.
        filter="udp and port 123": Captures only UDP packets on port 123 (NTP traffic).
        stop_filter=stop_filter: Stops sniffing when stop_sniffing is True.
    In the end, it writes received string to the log file.

    sniff_handler(pkt):
        In this function firstly, we check if this is not the first packet being processed. If it's not the first packet, the time elapsed since the last packet (current_time - last_packet_time) is printed for debugging. A new burst is detected if, this is the first packet (last_packet_time is None); or the time elapsed since the last packet exceeds the idle time. If the number of packets in the previous burst matches zero_packet_count, a "0" bit is appended to received_bits. Else if the number of packets in the previous burst matches one_packet_count, a "1" bit is appended to received_bits. Then, we reset the burst counter to 1, indicating the start of a new burst. If the current packet belongs to the same burst as the previous one, increment the burst counter and updates the timestamp of the last received packet. After that, we check if 8 bits have been received (a complete byte) and proceeds to decode it and extract the last 8 bits from received_bits and combine them into a binary string. Then we convert the 8-bit binary string into a character using a helper method. Then we append the decoded character to decoded_message and print it and clear the list of received bits to prepare for the next byte. If the termination character (".") has been received we set stop_sniffing to True to stop the sniffing process.

    stop_filter(pkt):
        Defines a function that stops packet sniffing when stop_sniffing is True.

This project demonstrates the implementation of a covert communication channel leveraging the timing and behavior of NTP packet bursts. By encoding binary messages into bursts of packets and carefully managing idle times, the system achieves reliable message transmission and decoding in a networked environment. The project highlights the potential for using network protocols in unconventional ways, showcasing a practical application of packet timing for information hiding. Through systematic design, including mechanisms for delay calculation, burst detection, and robust message logging, the project ensures that the covert channel functions effectively even under varying network conditions. This work underscores the importance of understanding network protocols not only for building secure systems but also for recognizing potential vulnerabilities that can be exploited for covert operations.