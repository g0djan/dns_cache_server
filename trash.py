# import asyncio
#
#
# class EchoServerProtocol:
#     def connection_made(self, transport):
#         self.transport = transport
#
#     def datagram_received(self, data, addr):
#         message = data.decode()
#         print('Received %r from %s' % (message, addr))
#         print('Send %r to %s' % (message, addr))
#         self.transport.sendto(data, addr)
#
#
# async def wakeup():
#     while True:
#         await asyncio.sleep(1)
#
#
# loop = asyncio.get_event_loop()
# coro = loop.create_datagram_endpoint(EchoServerProtocol, ('127.0.0.1', 8888))
# transport, async_protocol = loop.run_until_complete(coro)
#
# # add wakeup HACK
# asyncio.async(wakeup())
#
# try:
#     loop.run_forever()
# except KeyboardInterrupt:
#     pass
import json
import pickle


class Rap:
    pass

with open('cache', 'wb') as f:
    pickle.dump(Rap(), f)

with open('cache', 'rb') as f:
    a = pickle.load(f)
    print(a)