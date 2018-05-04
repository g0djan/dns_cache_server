import random
import socket
import time
import argparse

from dns_packet import DNSPacket, DNSQuery


class DNSClient:
    def resolve_name(self, name, type, address):
        query = DNSQuery(name, type)
        packet = DNSPacket()
        packet.id = random.getrandbits(16)
        packet.flags.recursion_desired = True
        packet.queries.append(query)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet.to_struct(), (address, 53))

        return self._receive(sock, packet.id)

    def _receive(self, sock, id, timeout=5):
        start_time = time.time()

        while (start_time + timeout - time.time()) > 0:
            try:
                resp, _ = sock.recvfrom(2048)
            except socket.timeout:
                break

            result = DNSPacket.from_struct(resp)
            if result.id != id:
                raise Exception("Got a message for another id")

            return result


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name',
                        type=str,
                        help='Domain name for resolving')
    parser.add_argument('--type',
                        type=str,
                        help='A or NS message available')
    return parser.parse_args()


if __name__ == '__main__':
    args = get_arguments()
    client = DNSClient()
    if args.type == 'A' or args.type == 'a':
        type = 1
    elif args.type == 'NS' or args.type == 'ns':
        type = 2
    else:
        print('Only A and NS request are supported')
        exit(1)
    response = client.resolve_name(args.name, type, '127.0.0.1')
    print(len(response.responses))
    for answer in response.responses:
        print(answer.rdata)
    print()
