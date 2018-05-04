import socket
import struct

from socket import inet_aton, inet_ntoa


def _pack_name(name):
    b = bytearray()
    for part in name.strip('.').split('.'):
        b.append(len(part))
        b += bytearray(part, 'latin1')
    b.append(0)
    return b


def _extract_string(data, blob):
    string = ''
    data = bytearray(data)
    while data and data[0] != 0:
        if data[0] & 0xc0:
            offset = int(data[0] ^ 0xc0) * 256 + int(data[1])
            string += _extract_string(blob[offset:], blob)[0]
            data = data[2:]
            return string, data
        else:
            string += data[1:1 + data[0]].decode('latin1') + '.'
            data = data[1 + data[0]:]
    return string, data[1:] if data else b''


def _append_resource_records(size, field, data, data_):
    for i in range(size):
        (name, data_) = _extract_string(data_, data)
        (response, data_) = DNSResponse.from_struct(name, data_, data)
        if response is not None:
            field.append(response)
    return data_


class DNSPacket:
    _PACKET_FORMAT = '!h '

    def __init__(self):
        self.id = None
        self.flags = DNSFlags()
        self.queries = []
        self.responses = []
        self.authorities = []
        self.additional = []

    def to_struct(self):
        id = struct.pack("!H", self.id)
        flags = self.flags.to_struct()
        header_rest = struct.pack(
            "!HHHH",
            len(self.queries),
            len(self.responses),
            len(self.authorities),
            len(self.additional))
        packed = bytearray()
        for item in (self.queries +
                     self.responses +
                     self.authorities +
                     self.additional):
            packed += item.to_struct()
        return id + flags + header_rest + packed

    @staticmethod
    def from_struct(data):
        packet = DNSPacket()
        (packet.id, _, qdcount,
         ancount, nscount, arcount) = struct.unpack_from('!HHHHHH', data)
        packet.flags = DNSFlags.from_struct(data[2:4])
        data_ = data[12:]
        for i in range(qdcount):
            (name, data_) = _extract_string(data_, data)
            (query, data_) = DNSQuery.from_struct(name, data_)
            if query is not None:
                packet.queries.append(query)

        data_ = _append_resource_records(ancount, packet.responses, data, data_)
        data_ = _append_resource_records(nscount, packet.authorities, data, data_)
        data_ = _append_resource_records(arcount, packet.additional, data, data_)
        return packet


class DNSFlags:
    def __init__(self):
        self.is_response = False
        self.op_code = 0  # standard request
        self.is_authority = False
        self.is_truncated = False
        self.recursion_desired = False
        self.recursion_available = False
        self.response_code = 0

    def to_struct(self):
        flags = 0
        flags |= self.is_response << 15
        flags |= (self.op_code % 16) << 11
        flags |= self.is_authority << 10
        flags |= self.is_truncated << 9
        flags |= self.recursion_desired << 8
        flags |= self.recursion_available << 7
        flags |= self.response_code % 15
        return struct.pack('!H', flags)

    @classmethod
    def from_struct(cls, data):
        (flags,) = struct.unpack_from("!H", data)
        this = cls()
        this.is_response = (flags & 0x8000) > 0
        this.op_code = (flags & 0x7800) >> 11
        this.is_authority = (flags & 0x0400) > 0
        this.is_truncated = (flags & 0x0200) > 0
        this.recursion_desired = (flags & 0x0100) > 0
        this.recursion_available = (flags & 0x0080) > 0
        this.response_code = (flags & 0x000f)
        return this


class DNSQuery:
    def __init__(self, name=None, type=None):
        self.name = name
        self.type = type
        self.cls = 1

    def to_struct(self):
        return _pack_name(self.name) + struct.pack('!HH', self.type, self.cls)

    @staticmethod
    def from_struct(name, data):
        (type, cls) = struct.unpack_from('!HH', data)
        return (DNSQuery(name, type), data[4:])


class DNSResponse:
    def __init__(self, name='', type=1, ttl=0, rdata=''):
        self.name = name
        self.type = type
        self.cls = 1
        self.ttl = ttl
        self.rdlength = len(rdata) if rdata is not None else 0
        self.rdata = rdata

    def to_struct(self):
        packed_rdata = inet_aton(self.rdata) if self.type == 1 else _pack_name(self.rdata)
        self.rdlength = len(packed_rdata)
        return (_pack_name(self.name) +
                struct.pack('!HHlH',
                            self.type,
                            self.cls,
                            self.ttl,
                            self.rdlength) +
                packed_rdata)

    @staticmethod
    def from_struct(name, data_, data):
        (type_, class_, ttl, rdlength) = struct.unpack_from('!HHlH', data_)
        rdata = data_[10:10 + rdlength]
        rdata = inet_ntoa(rdata) if type_ == 1 else _extract_string(rdata, data)[0]
        return DNSResponse(name, type_, ttl, rdata), data_[10 + rdlength:]


