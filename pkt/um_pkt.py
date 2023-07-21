#!/usr/bin/python
# Copyright Alex Zhao
# Simplified version of Umbrella
#  Packet filter
#  sockfilter  socket_fd
#  xdpfilter perf_output (xdp_output)
# attach to interface
#

class UmbrellaLSM:
    def __init__(self):
        """
        Initiate of UmbrellaPKT userspace 
        """
        