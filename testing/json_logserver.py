#!/usr/bin/env python

import SocketServer, json

class JSONLogServer(SocketServer.BaseRequestHandler):
    """
    Sample UDP server for receiving JSON messages.
    """

    def handle(self):
        data = self.request[0].strip()

        try:
            msg = json.loads(data)
            print "msg: %s\n" % msg
        except Exception, e:
            print e

if __name__ == "__main__":
    HOST, PORT = "localhost", 23456
    server = SocketServer.UDPServer((HOST, PORT), JSONLogServer)
    server.serve_forever()
