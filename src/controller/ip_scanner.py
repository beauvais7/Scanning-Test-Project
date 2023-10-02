from __future__ import annotations

from src.model.map_response import filter_results
from src.model.validation import verify_ip_format
from src.model.map_response import strip_junk

from src.util.format_response import clean_dict

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

        select_char = input("Enter IP here: ")

        while True:
            try:
                if verify_ip_format(select_char):
                    print(f"Beginning scan on {select_char}")

                    results = self.scan_given_ips(select_char)

                    directory = ""

                    for result in results:
                        if "False" in results:
                            directory = "False"
                        elif "True" in results:
                            directory = True

                        if result:
                            engine = clean_dict(result.keys())
                            version = clean_dict(result.values())
                            print(
                                f"Results for {select_char}: Engine Type: {engine}, Engine Version: {version}. Direct Listing: {directory}"  # noqa: E501
                            )
                            return True

                        else:
                            print(
                                f"Unable to determine Engine version or type for {select_char}"  # noqa: E501
                            )
                            return False

            except:  # noqa: E722
                print(
                    "Invalid entry. Please try again or close program by 'Ctrl C' "
                )  # noqa: E501
                select_char = input("Enter IP here: ")

    def scan_given_ips(self, ips: str) -> tuple[dict[str, str], str]:
        """Scan provided IPS for Engine Version"""

        scan_results = filter_results(
            self.nm_scanner.scan(ips, "80-443", "-sV"), ips
        )  # noqa: E501
        if not scan_results:
            return

        engine: dict[str, str] = {}
        port = ""
        for result in scan_results:
            if type(result) is int:
                port = result
                continue

            for key in result:
                if key in VALID_ENGINEES:
                    version = result.get(key)[0:3]
                    if version in VALID_ENGINEES.get(key):
                        engine[key] = version

        direct_listing = self.get_direct_listing(ips, port)

        return [engine, direct_listing]

    def get_direct_listing(self, ip_addr: str, port: str) -> str:
        """Check if index exists for website"""

        fqdn = socket.getfqdn(ip_addr)

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
                if (
                    "index" or "home.html" or "default.html" in web_results.text
                ):  # noqa: E501
                    return "True"

        except requests.exceptions.RequestException as err:
            if err:
                return "False"


if __name__ == "__main__":
    IPScanner().user_prompt()
