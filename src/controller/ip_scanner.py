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
            if not (addr_info['scan'][ip]):
                continue
            print(addr_info['scan'][ip])
            #print(addr_info['scan'][ip]['tcp'])
        return
            #for port in addr_info["scan"][ip]["tcp"]:
                #print(port.values())
            #else:
                #print(f"Unable to determine engine for IP Address: {ip}")
        
        #print(f'RESULTINGGGGGGGGGGGG: {results}')
        #return 
    """
    def scan_given_ips(self, ips: list[str]):
        ""Scan provided IPS for Engine Version""
        results: list[NMapData] = []
        for ip in ips:
            addr_info = NMapData(self.nm_scanner.scan(ip, '80-443', '-sV -O'), ip)
            if addr_info:
                results.append(addr_info)
            else:
                print(f"Unable to determine engine for IP Address: {ip}")
        
        print(f'RESULTINGGGGGGGGGGGG: {results}')
        return 
    """
if __name__ == "__main__":
    #scan_web_pages('cisco.com')
    #test_some()
    #self.test()
    IPS = ['8.8.8.8', '8.8.8.9']
    IPScanner().scan_given_ips(IPS)