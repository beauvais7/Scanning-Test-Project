from __future__ import annotations
from src.model.map_response import filter_results
from src.model.validation import verify_ip_format
from socket import *

import nmap

# Valid Engine Types
VALID_ENGINEES = {"iis": "7.0",  "nginx": "1.2"}


class IPScanner():
    def __init__(self):
        self.nm_scanner = nmap.PortScanner()

    def user_prompt(self):
        """User Prompt to receive IP address."""
        
        # Show User Menu, Save input
        print('Welcome!')
        print('Instructions: Enter an IP to scan.')
        print('Valid entry example: 8.8.8.9')

        # Get IP address from user
        select_char = input("Enter IP here: ")

        while True:
            try:
                if verify_ip_format(select_char):
                    print(f'Beginning scan on {select_char}')

                    # Call scanning function
                    results = self.scan_given_ips(select_char)
                    print(f'Any results? : {results}')
                    if results:
                        return True
                    if not results:
                        return False
            except:
                print("Invalid entry. Please try again or close program by 'Ctrl C' ")
                select_char = input("Enter IP here: ")

    def scan_given_ips(self, ips: str) -> dict[str[dict[str, str]]]:
        """Scan provided IPS for Engine Version"""

        results: dict[str[dict[str, str]]] = {}

        #for ip in ips:

        scan_results = filter_results(self.nm_scanner.scan(ips, '80-443', '-sV'), ips)
        if not scan_results:
            return

        #scan_results = {'nginx': '1.2.0'}
        #scan_results = {'iis': '7.0.8'}
        
        for result in scan_results:
            if result in VALID_ENGINEES:
                version = scan_results.get(result)[0:3]
                if version in VALID_ENGINEES.get(result):
                    results[ips] = {result: version}
            
        return results

if __name__ == "__main__":

    #IPS = ['52.54.102.4']
    
    #IPScanner().scan_given_ips(IPS)
    IPScanner().user_prompt()