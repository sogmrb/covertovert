import time
from CovertChannelBase import CovertChannelBase
from scapy.all import NTP, IP, UDP, sniff


class MyCovertChannel(CovertChannelBase):
    """
    Covert channel implementation using packet bursting with NTP packets.
    """

    def __init__(self):
        """
        Initialize the covert channel.
        """
        super().__init__()

    def calculate_delay(self, dest):
        """
        Calculate average network delay to determine idle time.
        """
        delays = []
        for _ in range(10):
            pkt = IP(dst=dest) / UDP() / NTP()
            start_time = time.time()
            super().send(pkt)
            delays.append(time.time() - start_time)

        avg_delay = sum(delays) / len(delays)
        print(f"Calculated average delay: {avg_delay}")
        return avg_delay

    def send(self, log_file_name, zero_packet_count, one_packet_count):
        """
        Send a random binary message using NTP packet bursts.
        """
        # Generate a random binary message
        binary_message = self.generate_random_binary_message_with_logging(
            log_file_name, min_length=40, max_length=40
        )
        idle_time = self.calculate_delay("receiver") * 4
        # message = "abcdefghiwjk."
        # binary_message = self.convert_string_message_to_binary(message)

        # print(f"Sending message: {message} with binary message {binary_message}")

        for bit in binary_message:
            pkt_list = []
            packet_count = one_packet_count if bit == "1" else zero_packet_count
            # print(f"Bit: {bit}, Sending {packet_count} packets.")

            for _ in range(packet_count):
                pkt = IP(dst="receiver") / UDP() / NTP()
                pkt_list.append(pkt)

            # Wait for idle time between bursts
            # print(f"Idle time before burst: {idle_time} seconds")
            time.sleep(idle_time)

            # Send the packets in the burst
            for pkt in pkt_list:
                super().send(pkt)

        # Send a final packet so receiver finishes its processing
        time.sleep(idle_time)
        super().send(IP(dst="receiver") / UDP() / NTP())
        time.sleep(idle_time)
        super().send(IP(dst="receiver") / UDP() / NTP())

    def receive(self, log_file_name, zero_packet_count, one_packet_count):
        """
        Sniff NTP packets and decode bursts into a binary message.
        """
        received_bits = []
        decoded_message = ""
        current_burst_count = 0
        last_packet_time = None
        idle_time = self.calculate_delay("sender") * 4
        stop_sniffing = False

        print(f"Idle time for burst detection: {idle_time}")

        def sniff_handler(pkt):
            nonlocal current_burst_count, last_packet_time, received_bits, decoded_message, stop_sniffing
            current_time = time.time()
            # print(f"Received packet at {current_time}")

            # Detect start of a new burst
            if last_packet_time is not None:
                print(f"Time passed: {current_time - last_packet_time}")
            if (
                last_packet_time is None
                or current_time - last_packet_time > idle_time + idle_time / 4
            ):
                print(
                    f"New burst detected. Previous burst count: {current_burst_count}"
                )

                # Decode the previous burst
                if current_burst_count == zero_packet_count:
                    received_bits.append("0")
                elif current_burst_count == one_packet_count:
                    received_bits.append("1")

                # print(f"Recently received byte: {''.join(received_bits)}")

                # Reset burst count for the new burst
                current_burst_count = 1
            else:
                # Increment current burst packet count
                current_burst_count += 1
                # print(f"Last burst count incremented: {current_burst_count}")

            last_packet_time = current_time

            # Decode the message after every 8 bits
            if len(received_bits) % 8 == 0 and len(received_bits) > 0:
                byte = "".join(received_bits[-8:])
                char = self.convert_eight_bits_to_character(byte)
                decoded_message += char
                print(f"Decoded character: {char}")
                received_bits.clear()

                if char == ".":
                    stop_sniffing = True

        def stop_filter(pkt):
            return stop_sniffing

        sniff(
            prn=sniff_handler,
            iface="eth0",
            stop_filter=stop_filter,
        )

        print(f"Final decoded message: {decoded_message}")
        self.log_message(decoded_message, log_file_name)
