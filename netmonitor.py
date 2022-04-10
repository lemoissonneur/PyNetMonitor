#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    ===========================================================================
    IP header info from RFC791
      -> http://tools.ietf.org/html/rfc791)

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ===========================================================================
    ICMP Echo / Echo Reply Message header info from RFC792
      -> http://tools.ietf.org/html/rfc792

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Identifier          |        Sequence Number        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Data ...
        +-+-+-+-+-

    ===========================================================================
"""

# =============================================================================#
import argparse
import os, sys, struct, time, signal
import socket, select

__description__ = "Monitor your network using ICMP echo request and raw sockets."

if sys.platform == "win32":  # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:  # On most other platforms it is time.time()
    default_timer = time.time

if sys.version[:1] != "3":
    print("This tool was made for python 3.X run at your own risk")

DEFAULT_PACKET_RATE = 10
DEFAULT_PACKET_SIZE = 1024
DEFAULT_DATA_RATE = DEFAULT_PACKET_RATE * DEFAULT_PACKET_SIZE
DEFAULT_TIMEOUT_MS = 3000
DEFAULT_VERBOSE = False

# =============================================================================#
# Network parameters
IP_HEADER_SIZE = 20  # size of IP header in bytes

ICMP_HEADER_SIZE = 8  # size of icmp header in bytes
ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer

PACKET_HEADER_SIZE = IP_HEADER_SIZE + ICMP_HEADER_SIZE
PACKET_ID_SIZE = struct.calcsize("Q")

MIN_PACKET_SIZE = IP_HEADER_SIZE + ICMP_HEADER_SIZE + struct.calcsize("Q")
MAX_PACKET_SIZE = ICMP_MAX_RECV

# =============================================================================#
class NetHealthMonitor:

    # settings
    targetIP = "0.0.0.0"
    icmpID = 0
    pktRate_Hz = DEFAULT_PACKET_RATE
    pktSize_bytes = DEFAULT_PACKET_SIZE
    timeout_ms = DEFAULT_TIMEOUT_MS
    verbose = DEFAULT_VERBOSE
    duration_sec = 0

    # status
    __pktsSent = 0
    __nextSendTime = 0
    __data = {}

    # controls
    __socket = None

    # =========================================================================#
    def __init__(
        self,
        target,
        pktRate_Hz=DEFAULT_PACKET_RATE,
        pktSize_bytes=DEFAULT_PACKET_SIZE,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        verbose=DEFAULT_VERBOSE,
        duration_sec=0,
    ):

        # get socket
        try:
            self.NetHealthMonitor__socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")
            )
        except socket.error as e:
            if self.verbose:
                print("failed. (socket error: '%s')" % e.args[1])
            raise e

        try:
            self.targetIP = socket.gethostbyname(target)
        except socket.gaierror as e:
            if self.verbose:
                print("\nUnknown host: %s (%s)" % (target, e.args[1]))
            raise e

        # Handle Ctrl-C
        signal.signal(signal.SIGINT, self.signal_handler)
        if hasattr(signal, "SIGBREAK"):  # Handle Ctrl-Break e.g. under Windows
            signal.signal(signal.SIGBREAK, self.signal_handler)

        self.icmpID = os.getpid() & 0xFFFF

        self.pktRate_Hz = pktRate_Hz
        if pktSize_bytes > ICMP_MAX_RECV:
            self.pktSize_bytes = ICMP_MAX_RECV
        elif pktSize_bytes < MIN_PACKET_SIZE:
            self.pktSize_bytes = MIN_PACKET_SIZE
        else:
            self.pktSize_bytes = pktSize_bytes
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        self.duration_sec = duration_sec

    # =========================================================================#
    def data_rate(self):
        return self.pktRate_Hz * self.pktSize_bytes

    # =========================================================================#
    def send_period(self):
        return 1 / self.pktRate_Hz

    # =========================================================================#
    def generate_packet(self):
        """
        Generate a new ping packet
        """

        # Make a dummy heder with a 0 checksum.
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, self.icmpID, 0)

        pktID = struct.pack("Q", self.__pktsSent)

        padData = "Z" * (self.pktSize_bytes - MIN_PACKET_SIZE)

        data = pktID + bytearray(padData, encoding="utf8")

        # Calculate the checksum on the data and the dummy header.
        myChecksum = checksum(header + data)  # Checksum is in network order

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, myChecksum, self.icmpID, 0)

        packet = header + data

        return packet

    # =========================================================================#
    def signal_handler(self, signum):
        """
        Handle exit via signals
        """
        self.NetHealthMonitor__socket.close()
        if self.verbose:
            print("\n(Terminated with signal %d)\n" % (signum))
        sys.exit(0)

    # =========================================================================#
    def output(self, pkt_id, send_time, delay, flag):
        print(str(pkt_id) + "," + str(send_time) + "," + str(delay) + "," + str(flag))

        return

    # =========================================================================#
    def send_ping(self, packet):
        """
        Send one ping to the given >destIP<.
        """
        sendTime = default_timer()
        self.__data[self.__pktsSent] = sendTime

        try:
            self.NetHealthMonitor__socket.sendto(packet, (self.targetIP, 1))
        except socket.error as e:
            flag = "General failure (%s)" % (e.args[1])
            self.output(self.__pktsSent, sendTime, -1, flag)
            del self.__data[self.__pktsSent]
            return None

        return sendTime

    # =========================================================================#
    def start_monitoring(self):
        """
        Start sending packet
        """

        if self.verbose:
            print("__ NETWORK HEALTH MONITOR __")
            print("destination IP, " + str(self.targetIP))
            print("--packet-rate, " + str(self.pktRate_Hz) + ", pkt/sec")
            print("--packet-size, " + str(self.pktSize_bytes) + ", bytes/pkt")
            print("--timeout, " + str(self.timeout_ms) + ", ms")
            print("--duration, " + str(self.duration_sec) + ", sec")
            print("##################################################")
            print("pkt_id, send_time, recv_delay, flag")

        start_time = default_timer()
        self.__nextSendTime = default_timer()

        if self.duration_sec > 0:
            end_time = start_time + self.duration_sec
            while end_time > default_timer():
                self.monitor()
        else:
            while True:
                self.monitor()

    # =========================================================================#
    def monitor(self):
        self.send_loop()
        self.recieve_loop()
        time.sleep(self.send_period() / 10)

        # check timeout
        pktIDtoDelete = []
        for pktID in self.__data.keys():
            if self.__data[pktID] + self.timeout_ms / 1000 < default_timer():
                self.output(pktID, self.__data[pktID], -1, "timeout")
                pktIDtoDelete.append(pktID)

        for id in pktIDtoDelete:
            del self.__data[id]

    # =========================================================================#
    def send_loop(self):
        """
        Handle packet send
        """

        if self.__nextSendTime <= default_timer():
            self.__pktsSent = self.__pktsSent + 1
            packet = self.generate_packet()
            self.send_ping(packet)
            self.__nextSendTime = self.__nextSendTime + self.send_period()

    # =========================================================================#
    def recieve_loop(self):
        """
        Handle packet rcv
        """
        whatReady = select.select([self.NetHealthMonitor__socket], [], [], 0)

        if whatReady[0] != []:  # recv
            recPacket, addr = self.NetHealthMonitor__socket.recvfrom(ICMP_MAX_RECV)

            icmpHeader = recPacket[IP_HEADER_SIZE : IP_HEADER_SIZE + ICMP_HEADER_SIZE]
            icmpType, icmpCode, icmpChecksum, icmpPacketID, icmpSeqNumber = struct.unpack(
                "!BBHHH", icmpHeader
            )

            if icmpPacketID == self.icmpID:  # Our packet
                dataSize = len(recPacket) - IP_HEADER_SIZE + ICMP_HEADER_SIZE
                pktID = recPacket[
                    PACKET_HEADER_SIZE : PACKET_HEADER_SIZE + PACKET_ID_SIZE
                ]
                pktID = struct.unpack("Q", pktID)[0]
                if pktID in self.__data:
                    self.output(
                        pktID,
                        self.__data[pktID],
                        default_timer() - self.__data[pktID],
                        "",
                    )
                    del self.__data[pktID]


# =============================================================================#
def checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if sys.byteorder == "little":
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        try:  # For Python3
            sum = sum + (hiByte * 256 + loByte)
        except:  # For Python2
            sum = sum + (ord(hiByte) * 256 + ord(loByte))
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string):  # Check for odd length
        loByte = source_string[len(source_string) - 1]
        try:  # For Python3
            sum += loByte
        except:  # For Python2
            sum += ord(loByte)

    sum &= 0xFFFFFFFF  # Truncate sum to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xFFFF)  # Add high 16 bits to low 16 bits
    sum += sum >> 16  # Add carry from above (if any)
    answer = ~sum & 0xFFFF  # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer


# =============================================================================#

# =============================================================================#
def main():

    parser = argparse.ArgumentParser(description=__description__)

    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")

    parser.add_argument(
        "-pr",
        "--packet-rate",
        type=float,
        default=DEFAULT_PACKET_RATE,
        help=("number of packets to be sent /seconds (default: %(default)s)"),
    )

    parser.add_argument(
        "-ps",
        "--packet-size",
        type=int,
        default=DEFAULT_PACKET_SIZE,
        help=(
            "number of data bytes to be sent per packet (default: %(default)s)"
            "("+ str(MIN_PACKET_SIZE) + "< packet size <" + str(MAX_PACKET_SIZE) + ")"
        ),
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_MS,
        help=("time to wait for a response in milliseconds (default: %(default)s)"),
    )

    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=0,
        help=("elapsed time before ending monitoring (default: none)"),
    )

    parser.add_argument("destination")
    args = parser.parse_args()

    MyMonitor = NetHealthMonitor(
        args.destination,
        args.packet_rate,
        args.packet_size,
        args.timeout,
        args.verbose,
        args.duration,
    )

    MyMonitor.start_monitoring()


if __name__ == "__main__":
    main()
