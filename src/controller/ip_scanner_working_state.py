from __future__ import annotations

#from requests import Response
#from bs4 import BeautifulSoup
#import requests
#import json
#import logging
#import time

from src.model.map_response import NMapData
from socket import *

import nmap

#RETRY = [429] + list(range(500, 600))
#MAX_RETRIES = 4

class IPScanner():
    def __init__(self):
        self.nm_scanner = nmap.PortScanner()

    def user_prompt():

        program = True
        while program:
            print("Welcome!")
            print("Instuctions:  ")
        # welcome message
        # description of program. 
        # how to use program

        #enforce checks by:
            #IP
            #string, bool, etc. to not crash program
            #put in error outputs, retry logic maybe a few times before exit.
            #
        return


    def scan_given_ips(self, ips: list[str]):
        """Scan provided IPS for Engine Version"""

        results: list[NMapData] = []
        for ip in ips:
            addr_info = self.nm_scanner.scan(ip, '80-443', '-sV -O')
            if addr_info['scan'] == {}:
                continue

            protocol = ""

            port_number = addr_info['scan'][ip]['tcp']
            if 443 in port_number:
                protocol = 443
            elif 80 in port_number:
                protocol = 80
            
            server_type = addr_info['scan'][ip]['tcp'][protocol]['product']
            if 'unknown' in server_type:
                print('Unable to determine Engine version or type.')
                continue

        return


if __name__ == "__main__":
    #scan_web_pages('cisco.com')
    #test_some()
    #self.test()
    IPS = ['8.8.8.8']
    
    IPScanner().scan_given_ips(IPS)