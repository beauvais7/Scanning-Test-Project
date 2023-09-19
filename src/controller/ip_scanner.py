from __future__ import annotations

#from requests import Response
#import requests
#import json
#import logging
#import time

from src.model.map_response import filter_results
from socket import *

#import nmap

#RETRY = [429] + list(range(500, 600))
#MAX_RETRIES = 4
VALID_ENGINEES = {"IIS": "7",  "Nginx": "1.2"}


       #enforce checks by:
            #IP
            #string, bool, etc. to not crash program
            #put in error outputs, retry logic maybe a few times before exit.
            #

class IPScanner():
    def __init__(self):
        #self.nm_scanner = nmap.PortScanner()
        self.user = socket

    def user_prompt(self):
        # Show User Menu, Save input
        print('Welcome!')
        print('Instructions: Enter an IP or set of IPs to scan. If multiple IPs, Ensure they are command separated.')
        print('Valid entry example: 8.8.8.8, 8.8.8.9')

        select_char = input("Enter IP here: ")

        if not select_char:
            print('No input entered. Exiting.')
        
        input_addresses: list[str] = []
        """
        program_okay = True
        while not program_okay:
            try:
                if select_char
        """


    def scan_given_ips(self, ips: list[str]):
        """Scan provided IPS for Engine Version"""

        results: list[str] = []

        for ip in ips:
            scan_results = filter_results(self.nm_scanner.scan(ip, '80-443', '-sV -O'), ip)
            if scan_results:
                if scan_results.keys() and scan_results.values() in VALID_ENGINEES:
                    print(f'Yes. Found {scan_results} ')
                else:
                    print(scan_results)
                    print(VALID_ENGINEES)

        return


if __name__ == "__main__":

    #IPS = ['8.8.8.8']
    
    #IPScanner().scan_given_ips(IPS)
    IPScanner().user_prompt()