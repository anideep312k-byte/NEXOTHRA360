"""Input validators."""
from __future__ import annotations
import ipaddress
import re


def is_valid_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved
    except ValueError:
        return False


def is_valid_email(email: str) -> bool:
    if not email:
        return False
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))
