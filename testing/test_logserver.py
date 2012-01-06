#!/usr/bin/env python

import sys, SocketServer

class JSONLogServer(SocketServer.BaseRequestHandler):
    """
    Sample UDP server for receiving JSON messages.
    """

    def handle_json(self, data):
        try:
            import json
            msg = json.loads(data)
            print("parsed json message:")
            for k in msg.keys():
                print(" %s: %s" % (k, msg[k]))
            print
        except Exception, e:
            print("json parsing error: %s" % e)

    def handle_netstr(self, data):
        try:
            import netstring
            decoder = netstring.Decoder()

            keys = [ "elevel", "sqlerrcode", "username", "database",
                     "remotehost", "funcname", "message", "detail",
                     "hint", "context ", "debug_query_string", ]
            pos = 0
            for field in decoder.feed(data):
                if pos < len(keys):
                    k = keys[pos]
                print(" %s: %s" % (k, field))
                pos += 1
        except Exception, e:
            print("netstr parsing error: %s" % e)

    def handle_syslog(self, data):
        pass

    def handle(self):
        data = self.request[0].strip()

        print("raw message: %s" % data)
        if not data:
            return

        if data.startswith("{"):
            self.handle_json(data)
        elif data[0].isdigit():
            self.handle_netstr(data)
        elif data[0] == '<':
            self.handle_syslog(data)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        PORT = 23456
    else:
        PORT = int(sys.argv[1])
    HOST = "localhost"

    print("Listening on %s:%s" % (HOST, PORT))
    server = SocketServer.UDPServer((HOST, PORT), JSONLogServer)
    server.serve_forever()
