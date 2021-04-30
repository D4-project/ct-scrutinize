#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
#
#

import redis
from M2Crypto import X509
import time
import base64
import os


r = redis.Redis(host='localhost', port=6379, db=15, socket_keepalive=True, socket_timeout=300)
p = r.pubsub()

p.subscribe('ct-certs', ignore_subscribe_messages=False)

m = False
certificate_path = '/certs'

def decode(cert_der = None):
    x509 = X509.load_cert_string(cert_der, X509.FORMAT_DER)
    subject = x509.get_subject().as_text()

def bpath(ha=None, level=6):
    if ha is None:
        return False
    fn = ""
    for i in range(0, level*2, 2):
        fn = fn + "/"+ ha[i:2+i]
    return fn


while True:
    try:
        m = p.get_message()
    except:
        r = redis.Redis(unix_socket_path="/tmp/redis.sock")
        p = r.pubsub()
        p.subscribe('ct-certs',
        ignore_subscribe_messages=False)
        m = p.get_message()

    if m:
        if type(m['data']) is int:
            print ("Skip non-related pub-sub message")
            continue
        cert_der = base64.b64decode(m['data'].rstrip())
        #decode(cert_der = cert_der)
        x509 = X509.load_cert_string(cert_der, X509.FORMAT_DER)
        try:
            subject = x509.get_subject().as_text()
        except:
            print("!!! Cannot get subject")
        fp = x509.get_fingerprint(md='sha1')
        filename = os.path.join(bpath(ha=fp).lower(), fp.lower())
        path = "{}{}".format("/certs", os.path.join(bpath(ha=fp).lower()))
        full_filename = "{}{}".format("/certs", filename)
        if not os.path.exists(path):
            os.makedirs(path)
        if os.path.exists(full_filename):
            print("Known certificate {} - {}".format(fp, subject))
            continue
        with open(full_filename, 'wb') as f:
            f.write(cert_der)
    time.sleep(0.001)

