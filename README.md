# PyNetMonitor
 Monitor your connection by sending custom sized pings at custom rate.
 
 ## usage
 
``` bash
usage: netmonitor.py [-h] [-v] [-pr PACKET_RATE] [-ps PACKET_SIZE] [-t TIMEOUT] [-d DURATION] destination

Monitor your network using ICMP echo request and raw sockets.

positional arguments:
  destination

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -pr PACKET_RATE, --packet-rate PACKET_RATE
                        number of packets to be sent /seconds (default: 10)
  -ps PACKET_SIZE, --packet-size PACKET_SIZE
                        data bytes per packet, min:36 max:2048 (default: 1024)
  -t TIMEOUT, --timeout TIMEOUT
                        time to wait for a response in milliseconds (default: 3000)
  -d DURATION, --duration DURATION
                        elapsed time before ending monitoring (default: none)
```