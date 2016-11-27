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
# SQLDB=Config.get("db", "db")
# SQLFILE=Config.get("db", "sql-create")
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

sqlite_file = 'dataSet.sqlite'
conn = sqlite3.connect(sqlite_file)
# c = conn.cursor()
fields = [ "parsed.fingerprint_sha256", "parsed.extensions.subject_alt_name.dns_names", "parsed.issuer_dn", "parsed.subject_dn", "parsed.signature_algorithm.name","parsed.signature.self_signed", "parsed.subject_key_info.key_algorithm.name","parsed.validity.start","parsed.validity.length","parsed.extensions.subject_alt_name.ip_addresses","parsed.extensions.subject_alt_name.directory_names.country","parsed.extensions.key_usage.encipher_only","parsed.extensions.key_usage.certificate_sign","parsed.extensions.key_usage.key_encipherment","parsed.extensions.key_usage.digital_signature", "parsed.extensions.key_usage.content_commitment","parsed.extensions.key_usage.decipher_only","parsed.extensions.key_usage.key_agreement","parsed.extensions.key_usage.data_encipherment"]



def getData(dom,cur):
    with conn:
        res = None
        # Contact the API
        # current_page = 1
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
        for i in  trange(metadata_pages):
            try:
                #while current_page <= 1:
                if res is None:
                    data = { 'query': dom, 'page': i, 'fields': fields}
                    data = json.dumps(data)
                    res = requests.post(API_URL + API_INDEX, data=data, auth=(UID,SECRET))
                    # print res.json()
                if "results" in res.json():
                    results = res.json()["results"]
                    # print results
                    for cert in results:
                        # columns = '"'+'", "'.join(cert.keys())+'"'
                        # cert = {k.replace(".",""): str(v) for k,v in cert.items()}
                        # placeholders = ':'+', :'.join(cert.keys())
                        conn.execute('INSERT INTO cert (domain,resultObj) VALUES (?,?)' , (dom, str(cert)))
                res = None
                # conn.commit()
                # time.sleep()
            except Exception as e:
                print e

try:
    # Create the database
    # cur.executescript(query)
    conn.execute('DROP TABLE IF EXISTS cert')
    conn.execute("CREATE TABLE cert(id INTEGER PRIMARY KEY   AUTOINCREMENT, domain TEXT, resultObj TEXT)")
    # print "CREATE TABLE cert("+" TEXT, ".join(x for x in fields)+")"
    for i in range(len(censys_queries)):
        print "++++++++++++++++++++++++++++++NEW_DOMAIN- %s ++++++++++++++++++++" %censys_queries[i]
        getData(censys_queries[i],conn)
    conn.close()
except Exception as e:
    conn.close()
    raise
