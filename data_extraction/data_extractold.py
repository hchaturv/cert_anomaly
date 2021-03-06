#!/usr/bin/python

# Use certificate transparancy for OSINT
#  information from censys
#
# Koen Van Impe
#   20160816
#
# Usage : censys.py myquery
#
# Configuration : see the censys.ini file
#

import sqlite3
import os
import os.path
import sys
import json
import requests
import ConfigParser
import time
from tqdm import *
from time import gmtime, strftime
# Setup the variables
Config = ConfigParser.ConfigParser()
Config.read("censys.ini.default")
SQLDB=Config.get("db", "db")
SQLFILE=Config.get("db", "sql-create")
API_URL = Config.get("censys", "url")
API_INDEX = Config.get("censys", "index")
UID = Config.get("censys", "uid")
SECRET = Config.get("censys", "secret")

# Censys Query
if len(sys.argv) <= 1 :
    print "error occurred: No censys filter given"
    print "Run %s censys_filter" % sys.argv[0]
    sys.exit(1)
censys_queries = sys.argv[1:]

print "0. Starting %s" % strftime("%Y-%m-%d %H:%M:%S", gmtime())

# Remove any old databases
if os.path.isfile(SQLDB):
    os.remove(SQLDB)
#Setup database
query = open(SQLFILE, 'r').read()
sqlite3.complete_statement(query)
conn = sqlite3.connect(SQLDB)
cur = conn.cursor()


def getData(dom,cur):
    with conn:

            res = None

            # Contact the API
            # current_page = 1
            fields = [ "parsed.fingerprint_sha256", "parsed.extensions.subject_alt_name.dns_names", "parsed.issuer_dn", "parsed.subject_dn", "parsed.signature_algorithm.name","parsed.signature.self_signed", "parsed.subject_key_info.key_algorithm.name","parsed.validity.start","parsed.validity.length","parsed.extensions.subject_alt_name.ip_addresses","parsed.extensions.subject_alt_name.directory_names.country","parsed.extensions.key_usage.encipher_only","parsed.extensions.key_usage.certificate_sign","parsed.extensions.key_usage.key_encipherment","parsed.extensions.key_usage.digital_signature", "parsed.extensions.key_usage.content_commitment","parsed.extensions.key_usage.decipher_only","parsed.extensions.key_usage.key_agreement","parsed.extensions.key_usage.data_encipherment"]
            data = { 'query': dom, 'page': 1, 'fields': fields}
            data = json.dumps(data)
            #print "This is the json i am sending: %s " %data
            res = requests.post(API_URL + API_INDEX, data=data, auth=(UID,SECRET))
            #print "Result code is : %s" %res

            # Check if we get a good reply
            if res.status_code != 200:
                print "error occurred: %s" % res.json()["error"]
                sys.exit(1)

            print "2. Received results for query %s" % censys_queries
            metadata_pages = res.json()["metadata"]["pages"]
            metadata_count = res.json()["metadata"]["count"]

            print "3. Got %s results in %s pages." % (metadata_count, metadata_pages)

            # while current_page <= metadata_pages:
            for i in trange(100):
                try:
                #while current_page <= 1:
                    if res is None:
                        data = { 'query': dom, 'page': i, 'fields': fields}
                        data = json.dumps(data)
                        while True:
                            res = requests.post(API_URL + API_INDEX, data=data, auth=(UID,SECRET))
                            if res.status_code == 200:
                                break
                            time.sleep(10)
                            print "error occurred: %s" % res.json()["error"]
                        #print res

                    # print "4. Page %s / %s " % (current_page, metadata_pages)

                    if "results" in res.json():
                        results = res.json()["results"]
                        # print results
                        for cert in results:
                            #print cert
                            try:
                                if "parsed.extensions.subject_alt_name.dns_names" in cert:
                                    dns_names = cert["parsed.extensions.subject_alt_name.dns_names"]
                                    dns_names_count = len(dns_names)
                                else:
                                    dns_names = None
                                    dns_names_count = 0
                                if "parsed.subject_dn" in cert:
                                    subject_dn = cert["parsed.subject_dn"][0]
                                else:
                                    subject_dn = None
                                if "parsed.extensions.subject_alt_name.directory_names.country" in cert:
                                    cntry = cert["parsed.extensions.subject_alt_name.directory_names.country"][0]
                                else:
                                    cnrty = None
                                if "parsed.issuer_dn" in cert:
                                    issuer_dn = cert["parsed.issuer_dn"][0]
                                else:
                                    issuer_dn = None
                                if "parsed.fingerprint_sha256" in cert:
                                    fingerprint_sha256 = cert["parsed.fingerprint_sha256"][0]
                                else:
                                    fingerprint_sha256 = None
                                if "parsed.signature_algorithm.name" in cert:
                                    sign_algo_name =  cert["parsed.signature_algorithm.name"][0]
                                else:
                                    sign_algo_name = None
                                if "parsed.signature.self_signed" in cert:
                                    self_signed = cert["parsed.signature.self_signed"][0]
                                else:
                                    self_Signed = None
                                if "parsed.subject_key_info.key_algorithm.name" in cert:
                                    key_algo = cert["parsed.subject_key_info.key_algorithm.name"][0]
                                else:
                                    key_algo = None
                                if "parsed.validity.length" in cert:
                                    val_length = cert["parsed.validity.length"]
                                else:
                                    val_length = None
                                if "parsed.extensions.key_usage.encipher_only" in cert:
                                    enc_only = cert["parsed.extensions.key_usage.encipher_only"][0]
                                else:
                                    enc_only = False
                                if "parsed.extensions.key_usage.certificate_sign" in cert:
                                    cert_sign = cert["parsed.extensions.key_usage.certificate_sign"][0]
                                else:
                                    cert_sign = False
                                if "parsed.extensions.key_usage.key_encipherment" in cert:
                                    key_enc = cert["parsed.extensions.key_usage.key_encipherment"][0]
                                else:
                                    key_enc = False
                                if "parsed.extensions.key_usage.digital_signature" in cert:
                                    digi_sign = cert["parsed.extensions.key_usage.digital_signature"][0]
                                else:
                                    digi_sign = False
                                if "parsed.extensions.key_usage.content_commitment" in cert:
                                    cont_commit = cert["parsed.extensions.key_usage.content_commitmenti"][0]
                                else:
                                    cont_commit = False
                                if "parsed.extensions.key_usage.decipher_only" in cert:
                                    dec_only = cert["parsed.extensions.key_usage.decipher_only"][0]
                                else:
                                    dec_only = False
                                if "parsed.extensions.key_usage.key_agreement" in cert:
                                    key_agreem = cert["parsed.extensions.key_usage.key_agreement"][0]
                                else:
                                    key_agreem = False
                                if "parsed.extensions.key_usage.data_encipherment" in cert:
                                    data_enc = cert["parsed.extensions.key_usage.data_encipherment"][0]
                                else:
                                    data_enc = False

                                issuer_c = ""
                                issuer_o = ""
                                issuer_cn = ""
                                issuer_ou = ""
                                if issuer_dn !=None:
                                    issuer_dn_split = issuer_dn.split(",")
                                    for el in issuer_dn_split:
                                        el = el.strip()
                                        if el[0:2] == "C=":
                                            issuer_c = el[2:]
                                        elif el[0:2] == "O=":
                                            issuer_o =  el[2:]
                                        elif el[0:3] == "CN=":
                                            issuer_cn = el[3:]
                                        elif el[0:3] == "OU=":
                                            issuer_ou = el[3:]

                                subject_c = ""
                                subject_o = ""
                                subject_cn = ""
                                subject_ou = ""
                                if subject_dn != None:
                                    subject_dn_split = subject_dn.split(",")
                                    for el in subject_dn_split:
                                        el = el.strip()
                                        if el[0:2] == "C=":
                                            subject_c = el[2:]
                                        elif el[0:2] == "O=":
                                            subject_o =  el[2:]
                                        elif el[0:3] == "CN=":
                                            subject_cn = el[3:]
                                        elif el[0:3] == "OU=":
                                            subject_ou = el[3:]

                                #subject_dn_table = [ fingerprint_sha256, subject_dn, dns_names_count, subject_c, subject_ou, subject_o, subject_cn]
                                #cur.execute("INSERT INTO subject_dn VALUES(?, ?, ?, ?, ?, ?, ?)", subject_dn_table)

                                #issuer_dn_table = [ fingerprint_sha256, issuer_dn, issuer_c, issuer_ou, issuer_o, issuer_cn]
                                #cur.execute("INSERT INTO issuer_dn VALUES(?, ?, ?, ?, ?, ?)", issuer_dn_table)

                                if val_length != None:
                                    val_length = int(val_length[0])
                                '''if val_start != None:
                                    val_start = str(val_start[0])[:10]'''

                                cert_data_table = [fingerprint_sha256, subject_cn, issuer_cn, sign_algo_name, self_signed, key_algo, val_length, enc_only, cert_sign, key_enc, digi_sign, cont_commit, dec_only, key_agreem, data_enc]
                                cur.execute("INSERT INTO "+dom+" VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", cert_data_table)

                                '''if dns_names is not None:
                                    for name in dns_names:
                                        dns_names_table = [ fingerprint_sha256, name ]
                                        cur.execute(INSERT INTO dns_names VALUES(?, ?), dns_names_table)
                                '''
                            except Exception as e:
                                print e, cert
                except Exception as e:
                    print e
                # conn.commit()
                # current_page += 1
                res = None
                time.sleep(2)



try:
    # Create the database
    # cur.executescript(query)
    print "1. Database %s created." % SQLDB
    for i in range(len(censys_queries)):
        cur.execute("CREATE TABLE "+censys_queries[i]+" (sha256 TEXT, content TEXT, subject_c TEXT, subject_o TEXT, subject_cn TEXT, issuer_c TEXT, issuer_o TEXT, signing_algorithm TEXT, self_signed BOOL, key_algorithm TEXT, val_start, val_length INT, enc_only BOOL,cert_sign BOOL, key_enc BOOL, digi_sign BOOL, cont_commit BOOL,dec_only BOOL, key_agreem BOOL, data_enc BOOL)")
        print "++++++++++++++++++++++++++++++NEW_DOMAIN- %s ++++++++++++++++++++" %censys_queries[i]
        getData(censys_queries[i],cur)
    cur.close()
except Exception as e:
    cur.close()
    raise
