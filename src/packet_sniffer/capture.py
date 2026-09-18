"""Capture packets and store IP traffic metadata in Supabase."""

import os
from functools import lru_cache

from scapy.all import IP, IPv6, sniff
from supabase import Client, create_client


@lru_cache(maxsize=1)
def get_supabase_client() -> Client:
    """Read environment variables inherited from the launching shell."""
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("Set SUPABASE_URL and SUPABASE_KEY before starting capture.")
    return create_client(url, key)


def capture_packets(interface: str | None = None, count: int = 10):
    """Capture a limited number of packets from the selected interface."""
    return sniff(iface=interface, count=count, store=True)


def insert_packets_to_db(packets):
    """Insert IP metadata; protocol is the numeric IP protocol identifier.

    Payload size is the number of bytes in the IP-layer payload, including
    transport headers. Non-IP packets are skipped.
    """
    records = []
    for packet in packets:
        if IP in packet:
            layer = packet[IP]
            protocol = int(layer.proto)
        elif IPv6 in packet:
            layer = packet[IPv6]
            protocol = int(layer.nh)
        else:
            continue
        records.append({
            "source_ip": layer.src,
            "destination_ip": layer.dst,
            "protocol": protocol,
            "payload_size": len(bytes(layer.payload)),
        })

    if not records:
        return None
    return get_supabase_client().table("network_traffic").insert(records).execute()


if __name__ == "__main__":
    get_supabase_client()
    print("Capturing and inserting batches of 10 packets. Press Ctrl+C to stop.")
    try:
        while True:
            packets = capture_packets(count=10)
            insert_packets_to_db(packets)
    except KeyboardInterrupt:
        print("Packet capture stopped.")
