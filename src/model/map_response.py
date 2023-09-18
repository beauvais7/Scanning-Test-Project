"""Data Model for sifting those nmap results"""

from __future__ import annotations
from typing import Any
from dataclasses import dataclass


@dataclass(frozen=True)
class NMapData:
    scan: dict[str, Any]
    ip_address: str

    @classmethod
    def from_results(cls, results: dict[str, Any], ip_add: str) -> NMapData:
        """Build a data class from nmap results"""
        filter_results = results["scan"][ip_add]["tcp"]

        print(f'1. {filter_results}')
        for result in filter_results:
            print(f'2. {result}')
            if '443' or '80' not in result:
                return None

        return cls(
            scan=results["scan"][ip_add]["tcp"]
        )
