from __future__ import annotations
from src.model.map_response import filter_results
from src.model.validation import verify_ip_format
from src.model.map_response import strip_junk

import socket

import nmap
import requests

# Valid Engine Types
VALID_ENGINEES = {"iis": "7.0", "nginx": "1.2"}


class IPScanner:
    def __init__(self):
        self.nm_scanner = nmap.PortScanner()
        self.socket = socket

    def user_prompt(self):
        """User Prompt to receive IP address."""

        # Show User Menu, Save input
        print("Welcome!")
        print("Instructions: Enter an IP to scan.")
        print("Valid entry example: 8.8.8.9")

        # Get IP address from user
        select_char = input("Enter IP here: ")

        while True:
            try:
                if verify_ip_format(select_char):
                    print(f"Beginning scan on {select_char}")
                    # Call scanning function
                    results = self.scan_given_ips(select_char)
                    if results:
                        print(f"Results for {select_char}. Direct Listing: {results}")
                        return True
                    if not results:
                        print(
                            f"Unable to find version match for provided {select_char}"
                        )
                        return False
            except:
                print("Invalid entry. Please try again or close program by 'Ctrl C' ")
                select_char = input("Enter IP here: ")

    def scan_given_ips(self, ips: str) -> tuple[dict[str, str], str]:
        """Scan provided IPS for Engine Version"""

        results: dict[str, str] = {}

        # for ip in ips:
        scan_results = filter_results(self.nm_scanner.scan(ips, "80-443", "-sV"), ips)
        if not scan_results:
            return

        engine: dict[str, str] = {}
        port = ""
        for result in scan_results:
            if type(result) == int:
                port = result
                continue
            for key in result:
                if key in VALID_ENGINEES:
                    version = result.get(key)[0:3]
                    if version in VALID_ENGINEES.get(key):
                        engine[key] = version

        direct_listing = self.get_direct_listing(ips, port)

        return results, direct_listing

    def get_direct_listing(self, ip_addr: str, port: str) -> bool:
        """Check if index exists for website"""

        fqdn = socket.getfqdn(ip_addr)

        # Function to strip bad url information
        domain_name = strip_junk(fqdn)

        hyper_link = ""
        if port:
            if port == 443:
                hyper_link = "https://"
            elif port == 80:
                hyper_link = "http://"

        try:
            web_results = requests.get(f"{hyper_link}{domain_name}")

            if web_results:
                if ".index" in web_results.text:
                    return True
        except requests.exceptions.RequestException as err:
            if err:
                return False


if __name__ == "__main__":
    IPScanner().user_prompt()
