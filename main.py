import socket
from typing import List, Union

from message import (
    parse_message,
    Message,
    construct_query,
    QTypes,
    QClasses,
    Label,
    domain_from_labels,
    construct_response,
)


def handle_query(s: socket.socket, data, emitter):
    m = parse_message(data)
    if m.question[0].qtype != QTypes.A_RECORD or m.question[0].qclass != QClasses.IN:
        raise ValueError("I don't handle these kind of queries. Only basic baby-dns queries please.")

    ip, ttl = get_ip(m.question[0].qname)
    response = construct_response(m.header.transaction_id, m.question[0].qname, ip, ttl)
    s.sendto(response.to_bytes(), emitter)


def get_ip(domain: Union[str, List[Label]]):
    ip = "192.203.230.10"  # A root server

    while True:
        new_query = construct_query(domain)
        response = send_query(new_query, ip)

        for a in response.answer + response.additional:
            if a.type == QTypes.A_RECORD:
                domain_str = domain_from_labels(domain) if isinstance(domain, list) else domain
                if domain_from_labels(a.name) == domain_str:
                    ip, ttl = a.rd_data_as_ip, a.ttl_s
                    print(f"Found IP for {domain}: {ip}")
                    return ip, ttl

        ns_domain = response.authority[0].rd_data_as_labels
        # recursive call to get the ip of the nameserver. Then we can use that to ask it for our domain.
        ip, ttl = get_ip(ns_domain)


def send_query(query: Message, ip: str) -> Message:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(query.to_bytes(), (ip, 53))
    # not sure whether the max size is standard. This is big (TM) so it should be alright for simple queries.
    msg_bytes, _ = s.recvfrom(65535)
    msg = parse_message(msg_bytes)
    return msg


def main():
    host, port = "127.0.0.1", 9000
    # SOCK_DGRAM for a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"listening on {host}:{port}")

    while True:
        data, client_addr = server_socket.recvfrom(4096)
        # I removed multithreading because there's no point. Also a lot easier to debug without it.
        handle_query(server_socket, data, client_addr)


if __name__ == "__main__":
    main()
