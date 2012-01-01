#!/usr/bin/env python

import sys, SocketServer, json

class JSONLogServer(SocketServer.BaseRequestHandler):
    """
    Sample UDP server for receiving JSON messages.
    """

    def handle(self):
        data = self.request[0].strip()

        print("json message: %s" % data)

        try:
            msg = json.loads(data)
            print("parsed message:")
            for k in msg.keys():
                print(" %s: %s" % (k, msg[k]))
        except Exception, e:
            print(e)

if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        PORT = 23456
    else:
        PORT = int(sys.argv[1])
    HOST = "localhost"
    print("Listening on %s:%s" % (HOST, PORT))
    server = SocketServer.UDPServer((HOST, PORT), JSONLogServer)
    server.serve_forever()
