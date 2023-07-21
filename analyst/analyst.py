#!/usr/bin/python
# Copyright Alex Zhao
#
#  Analyst for data analysis called by Monitor
#
#  consume data from EventMonitor (collected from probes)
#  initiate reaction to UmLsm

class Analyst:
    def __init__(self, config):
        """
        Analyst
        """
        self.debug = False
    
    def consume(self, event):
        """
        Consume nw monitored events
        1. analysis by Analyst module for simple reaction
        2. push for prophet for take reaction
        """
        