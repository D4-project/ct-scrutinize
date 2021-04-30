#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys
import datetime
import certstream
from M2Crypto import X509
import redis

def decode(cert_der = None):
    x509 = X509.load_cert_string(cert_der, X509.FORMAT_DER)
    subject = x509.get_subject().as_text()

def print_callback(message, context):
    logging.debug("Message -> {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']


        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        sys.stdout.write(u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert'
]['all_domains'][1:])))
        cert_der = str(message['data']['leaf_cert']['as_der'])
        #sys.stdout.write(u"{}\n".format(str(message['data']['leaf_cert']['as_der'])))
        r.publish('ct-certs', u"{}\n".format(str(message['data']['leaf_cert']['as_der'])))
        sys.stdout.flush()


r = redis.Redis(host='localhost', port=6379, db=15)
logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback, url='ws://crd.circl.lu:4000/full-stream')

