#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
#
#

import redis
from M2Crypto import X509
import time
import base64
import os
import dns.resolver
import xxhash


#r = redis.Redis(host='localhost', port=6379, db=15, socket_keepalive=True, socket_timeout=300)
r = redis.Redis(unix_socket_path="/tmp/redis.sock")
p = r.pubsub()

p.subscribe('ct-certs', ignore_subscribe_messages=False)

m = False

common_names = ['www', 'mail', '', 'host', 'router', 'ns', 'gw', 'server']

resolver = dns.resolver.Resolver()
resolver.timeout = 1
resolver.lifetime = 1
time_to_expire = 3000

def cache(value = None, time_to_expire = time_to_expire):
    if value is None:
        return False
    r.set(hash_to_query, to_query)
    r.expire(hash_to_query, time_to_expire)
    return True

while True:
    try:
        m = p.get_message()
    except:
        r = redis.Redis(unix_socket_path="/tmp/redis.sock")
        p = r.pubsub()
        p.subscribe('ct-certs', ignore_subscribe_messages=False)
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

        try:
            cAltName = x509.get_ext('subjectAltName').get_value()
        except LookupError:
            cAltName = ""
        dns_entry = str(subject).split("=")[1]
        if dns_entry.startswith('*'):
            for common_name in common_names:
                dns_to_query = dns_entry.replace("*", common_name)
                hash_dns_to_query = xxhash.xxh128_hexdigest(dns_to_query)
                if r.exists(hash_dns_to_query):
                    print("Already seen")
                    continue
                cache(value=hash_dns_to_query)
                if dns_to_query.startswith('.'):
                    dns_to_query = dns_to_query.replace(".", "")
                    r.ping()
                answers = None
                try:
                    answers = resolver.resolve(dns_to_query, 'AAAA')
                except:
                    pass
                    #print("-- NX {}".format(dns_to_query))
                if answers is None: continue
                for rdata in answers:
                    print(rdata)

        for altname in cAltName.split(','):
            to_query = altname.split(":")[1]
            r.ping()
            hash_to_query = xxhash.xxh128_hexdigest(to_query)
            if r.exists(hash_to_query):
                print("Already seen")
                continue
            cache(value=hash_to_query)
            answers = None
            try:
                answers = resolver.resolve(to_query, 'AAAA')
            except:
                pass
                #print("-- NX {}".format(to_query))
            if answers is None: continue
            for rdata in answers:
                print(rdata)

    time.sleep(0.001)

