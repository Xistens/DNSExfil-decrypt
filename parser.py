#!/usr/bin/python3
import sys
import os
from scapy.all import DNSRR, rdpcap
from base64 import b64decode
import binascii
import argparse


class RC4:
    # https://github.com/Arno0x/DNSExfiltrator/blob/master/dnsexfiltrator.py
    def __init__(self, key = None):
        self.state = list(range(256))
        self.x = self.y = 0

        if key is not None:
            self.key = key
            self.init(key)
    
    def init(self, key):
        for i in range(256):
            self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0
    
    def binaryDecrypt(self, data):
        output = [None] * len(data)
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)

def base64URL_decode(msg):
    # https://github.com/Arno0x/DNSExfiltrator/blob/master/dnsexfiltrator.py
    msg = msg.replace("_", "/").replace("-", "+")
    if len(msg) % 4 == 3:
        return b64decode(msg + "=")
    elif len(msg) % 4 == 2:
        return b64decode(msg + "==")
    else:
        return b64decode(msg)

def main(passwd, pcap_file):
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(DNSRR):
            if isinstance(packet.an, DNSRR):
                curr = packet.an.rrname.decode("utf-8")
                # Find all indices of "."
                i = [i for i,c in enumerate(curr) if c == "."]
                # Remove domain
                curr = curr[0:i[-3]]
                num, data = curr.split(".", 1)
                chunks = []
                chunks.append(data.replace(".", ""))
                curr = "".join(chunks)

                rc4_decode = RC4(passwd)
                data = rc4_decode.binaryDecrypt(bytearray(base64URL_decode(curr)))

                with open(num, "wb") as fd:
                    fd.write(data)

def parse_args(args):
    """ Create the arguments """
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="infile", help="pcap file")
    parser.add_argument("-p", dest="passwd", help="Password to decode RC4")

    if len(sys.argv) < 2:
        parser.print_help()
        exit()
    
    argsp = parser.parse_args(args)
    if not argsp.infile:
        parser.print_help()
        exit()
    return argsp

if __name__ == "__main__":
    options = parse_args(sys.argv[1:])
    if os.path.isfile(options.infile):
        main(options.passwd, options.infile)
    else:
        raise FileNotFoundError("Cannot find the file '{}'".format(options.infile))

