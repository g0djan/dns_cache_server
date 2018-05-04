import random
from datetime import datetime, timedelta

from dns_packet import DNSPacket, DNSResponse

root_servers = {('a.root-servers.net', 1): {'198.41.0.4': None},
                ('b.root-servers.net', 1): {'192.9.14.201': None},
                ('c.root-servers.net', 1): {'192.33.4.12': None},
                ('d.root-servers.net', 1): {'199.7.91.13': None},
                ('e.root-servers.net', 1): {'192.203.230.10': None},
                ('f.root-servers.net', 1): {'192.5.5.241': None},
                ('g.root-servers.net', 1): {'192.112.36.4': None},
                ('h.root-servers.net', 1): {'198.97.190.53': None},
                ('i.root-servers.net', 1): {'192.36.148.17': None},
                ('j.root-servers.net', 1): {'192.58.128.30': None},
                ('k.root-servers.net', 1): {'193.0.14.129': None},
                ('l.root-servers.net', 1): {'199.7.83.42': None},
                ('m.root-servers.net', 1): {'202.12.27.33': None},

                ('.', 2): {'a.root-servers.net': None,
                           'b.root-servers.net': None,
                           'c.root-servers.net': None,
                           'd.root-servers.net': None,
                           'e.root-servers.net': None,
                           'f.root-servers.net': None,
                           'g.root-servers.net': None,
                           'h.root-servers.net': None,
                           'i.root-servers.net': None,
                           'j.root-servers.net': None,
                           'k.root-servers.net': None,
                           'l.root-servers.net': None,
                           'm.root-servers.net': None
                           }
                }


class Cache:
    def __init__(self):
        self._cache = root_servers

    def update(self, packet: DNSPacket):
        for response in (packet.responses +
                         packet.authorities +
                         packet.additional):
            if response.ttl == 0 or response.type > 2:
                continue
            expired_time = datetime.now() + timedelta(seconds=response.ttl)
            request = (response.name, response.type)
            if request not in self._cache:
                self._cache[request] = {}
            self._cache[request][response.rdata] = expired_time

    def _flush_old(self):
        to_delete = []
        for records in self._cache.values():
            for record in records:
                if records[record] is not None and records[record] < datetime.now():
                    to_delete.append(record)
            for to_del in to_delete:
                records.pop(to_del, None)


    def get(self, name, type):
        self._flush_old()
        record = self._cache.get((name, type))
        if record is None or len(record) == 0:
            return None
        record = list(record.keys())
        return random.choice(record)

    def get_all(self, name, type):
        self._flush_old()
        record = self._cache.get((name, type))
        if record is None or len(record) == 0:
            return None
        packet = DNSPacket()
        for rdata in record:
            resp = DNSResponse()
            resp.rdata = rdata
            resp.name = name
            resp.type = type
            packet.responses.append(resp)
        return packet