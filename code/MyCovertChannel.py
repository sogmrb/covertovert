import time
from CovertChannelBase import CovertChannelBase
from scapy.all import NTP, IP, UDP, sniff


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

    def __init__(self):
        """
        - You can edit __init__.
        """

    def send(self, log_file_name, zero_packet_count, one_packet_count):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        network_delay = self.calculate_delay("receiver")
        idle_time = network_delay * 2
        print(f"binary message: {binary_message}")
        for bit in binary_message:
            pkt_list = []
            print(f"bit:{bit}")
            print(
                f"zero_packet_count: {zero_packet_count}, one_packet_count: {one_packet_count}"
            )
            packe_count = one_packet_count if bit == "1" else zero_packet_count
            for i in range(packe_count):
                # construct NTP packets and append them to list
                pkt = IP(dst="receiver") / UDP() / NTP()
                pkt_list.append(pkt)

            print(f"length: {len(pkt_list)}")
            for pkt in pkt_list:
                super().send(pkt)

            print(f"idle_time: {idle_time}")
            time.sleep(idle_time)

    def receive(self, log_file_name, zero_packet_count, one_packet_count):
        """
        Sniffs packets and decodes bursts into a message until the stopping character '.' is received.
        """
        received_bits = []
        decoded_message = []
        current_burst_count = 0
        last_packet_time = None
        idle_time = self.calculate_delay("sender") * 2

        def sniff_handler(pkt):
            print("inside sniff handler")
            print(f"Received packet: {pkt.summary()}")
            nonlocal current_burst_count, last_packet_time, received_bits, decoded_message
            current_time = time.time()
            print(f"idle time: {idle_time}")
            if last_packet_time:
                print(
                    f" current_time - last_packet_time = {current_time - last_packet_time}"
                )

            # detect start of a new burst. add some approximation to idle time. is 5ms good?
            if last_packet_time is None or current_time - last_packet_time > idle_time:
                print("beginning of burst")
                print(f"burst count: {current_burst_count}")
                # current burst
                if current_burst_count == zero_packet_count:
                    received_bits.append("0")
                elif current_burst_count == one_packet_count:
                    received_bits.append("1")

                print(f"received bits:{received_bits}")

                # new burst
                current_burst_count = 1
            else:
                # keep counting packets for current burst
                current_burst_count += 1

            last_packet_time = current_time

            if len(received_bits) % 8 == 0 and len(received_bits) > 0:
                byte = "".join(received_bits[-8:])
                print(f"byte: {byte}")
                char = self.convert_eight_bits_to_character(byte)
                print(f"received char:{char}")

                if char == ".":
                    decoded_message.append(char)
                    raise StopIteration
                else:
                    decoded_message.append(char)
                print(f"decoded_message:{decoded_message}")

        try:
            print("before sniff")
            sniff(prn=sniff_handler, iface="eth0")
        except StopIteration:
            pass

        final_message = "".join(decoded_message)
        self.log_message(final_message, log_file_name)

    def calculate_delay(self, dest):
        """
        Measures and returns the average network delay between sending packets.
        This delay is used to ensure idle time is not interpreted as network delay.
        """
        delays = []
        for _ in range(10):
            pkt = IP(dst=dest) / UDP() / NTP()
            start_time = time.time()
            super().send(pkt)
            delays.append(time.time() - start_time)

        avg_delay = sum(delays) / len(delays)
        return avg_delay
