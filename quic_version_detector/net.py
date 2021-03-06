import socket

from . import quic


BIND_PORT = 5467
RECV_PACKET_SIZE = 1400


def send_recv_packet(addr: str, port: int, packet: quic.Packet) -> bytes:
    """Sends a UDP packet and waits for response.

    Returns:
        response from the server.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', BIND_PORT))
    sock.sendto(packet.to_buff(), (addr, port))
    buff, _ = sock.recvfrom(RECV_PACKET_SIZE)
    return buff


def parse_hostname_ip(addrinfo) -> str:
    """Gets IP address from sock.getaddrinfo result.

    Returns:
        IP address to which some hostname resolves.
    """
    if len(addrinfo) == 0:
        return None

    _, _, _, _, socket_addr = addrinfo[0]
    ip_addr, _ = socket_addr

    return ip_addr


def resolve_hostname(hostname: str, port: int=None) -> str:
    """DNS resolve hostname.

    Args:
        hostname: hostname to get IP address for.
        port: optional. Used to hint what DNS entry we're looking
            for.

    Returns:
        IP address used to connect to the specified hostname.
    """
    try:
        return parse_hostname_ip(
            socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_DGRAM)
        )
    except socket.gaierror:
        return None
