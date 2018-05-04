import asyncio
import json
import pickle
import signal
import psutil

from cache import Cache
from dns_client import DNSClient
from dns_packet import DNSPacket, DNSQuery, DNSResponse

ATTEMPS_CNT = 50


async def wakeup():
    while True:
        await asyncio.sleep(1)

class DNSResolverProtocol:
    def __init__(self, ttl, server):
        self.ttl = ttl
        self.server = server

    def connection_made(self, transport):
        print('Connected')
        self.transport = transport

    def datagram_received(self, data, addr):
        print('Datagram received')
        packet = DNSPacket.from_struct(data)
        self.server.cache.update(packet)
        responses = []
        for query in packet.queries:
            answer = self.handle(query)
            if not answer:
                print("can't resolve")
                continue
            packet.flags.is_authority = answer.flags.is_authority
            responses += answer.responses
        self.reply(packet.id, packet.queries, responses, addr)

    def handle(self, query):
        response = self.server.cache.get_all(query.name, query.type)
        if response:
            return response

        for attemp in range(ATTEMPS_CNT):
            known_server = self._get_known_server_name(query)
            known_server_address = self.server.cache.get(known_server, 1)
            if not known_server_address:
                q = DNSQuery(known_server, 1)
                h = self.handle(q)
                if not h:
                    return
                self.server.cache.update(h)
                known_server_address = self.server.cache.get(known_server, 1)

            response = self.server.client.resolve_name(query.name, query.type, known_server_address)
            if not response:
                return None
            self.server.cache.update(response)
            if len(response.responses) > 0:
                return response

    def _get_known_server_name(self, query):
        index = 0
        path_parts = query.name.strip('.').split('.')
        known_server = None
        while index <= len(path_parts):
            name = '.'.join(path_parts[index:]) + '.'
            known_server = self.server.cache.get(name, 2)
            if known_server:
                break
            index += 1
        return known_server

    def reply(self, id, queries, responses, addr):
        reply = DNSPacket()
        reply.id = id
        reply.flags.is_response = True
        reply.flags.op_code = 0
        reply.flags.is_authority = False
        reply.flags.is_truncated = False
        reply.flags.response_code = 0
        reply.flags.recursion_desired = True
        reply.flags.recursion_available = True
        reply.queries = queries
        reply.responses = responses
        self.transport.sendto(reply.to_struct(), addr)


class DNSServer:
    _PORT = 53

    def __init__(self, ttl):
        self.client = DNSClient()
        self.loop = asyncio.get_event_loop()
        self.free_port()
        self.listen = self.loop.create_datagram_endpoint(
            lambda: DNSResolverProtocol(ttl, self),
            local_addr=('127.0.0.1', DNSServer._PORT))
        self.cache = Cache()
        self.load_cache()


    def load_cache(self):
        try:
            with open('cache', 'rb') as f:
                self.cache = pickle.load(f)
        except:
            print("loading cache failed")
        self.cache._flush_old()

    def run(self):
        transport, async_protocol = self.loop.run_until_complete(self.listen)
        asyncio.async(wakeup())
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            transport.close()
            self.loop.close()

            with open('cache', 'wb') as f:
                pickle.dump(self.cache, f)



    def free_port(port=_PORT):
        for process in psutil.process_iter():
            for connection in process.connections(kind='inet'):
                if connection.laddr.port == port:
                    process.send_signal(signal.SIGTERM)
                    continue


if __name__ == '__main__':
    server = DNSServer(10000)
    server.run()
