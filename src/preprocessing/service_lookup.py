"""
Maps destination port numbers to NSL-KDD-style service names.
NSL-KDD uses ~70 service categories; we cover the most common ones
and default anything unknown to 'other' or 'private' (matching dataset convention).
"""

PORT_TO_SERVICE = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    53: "domain",
    79: "finger",
    80: "http",
    88: "kerberos",  # not in original NSL-KDD but common today
    109: "pop_2",
    110: "pop_3",
    111: "sunrpc",
    113: "auth",
    119: "nntp",
    123: "ntp_u",
    139: "netbios_ssn",
    143: "imap4",
    161: "snmp",
    179: "bgp",
    194: "irc",
    389: "ldap",
    443: "http",       # https treated as http in classic NSL-KDD
    443: "http_443",   # alt label some NSL-KDD versions use
    513: "login",
    514: "shell",
    515: "printer",
    540: "uucp",
    543: "klogin",
    544: "kshell",
    993: "imap4",
    995: "pop_3",
    1433: "sql_net",
    2049: "nfs",
    3306: "sql_net",
    6000: "X11",
    6667: "irc",
    8080: "http",
}

# Service names that NSL-KDD treats specially based on port RANGES
def get_service(port: int, protocol: str = "tcp") -> str:
    """
    Returns the NSL-KDD-style service name for a given port.
    Falls back to 'private' for unrecognized high ports (>= 1024),
    or 'other' for unrecognized low/reserved ports.
    """
    if port in PORT_TO_SERVICE:
        return PORT_TO_SERVICE[port]

    if protocol == "icmp":
        return "eco_i"  # most common ICMP echo request label in NSL-KDD

    if port >= 1024:
        return "private"

    return "other"