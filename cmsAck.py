# Andrew Danis
# 7/5/19

import requests
import sys
import argparse

baseurl="https://localhost/wsapis/v2.0.0/"
ackurl = 'https://localhost/wsapis/v2.0.0/alerts/alert/'
user = 'api'
pwd = ''

def __init__(self):
    parser = argparse.ArgumentParser(
        description='Acknowledges Alerts in Fire Eye NX/CMS',
        usage='''\tcmsAck.py [<args>]
        
        List of args:
   \tuuid         UUID of Alert to Acknowledge
   \ttype         Alert Type of Alert to Acknowledge
  
''')


# Thanks https://github.com/ktneely/ir-scripts/blob/master/IncMgmt/feapi.py
def cmsauth(user, pwd):
    # Authenticate with the CMS and return a temporary API token
    authurl = baseurl + 'auth/login'
    cms = requests.post(authurl, auth=(user, pwd), verify=False)
    # print(cms.url, cms.headers, cms.request.body)
    # print(cms.status_code)
    # print(cms.headers)
    if cms.status_code is 200:
        print("Authentication successful")
    else:
        print("Authentication Failure")
        print(cms.status_code)
    token = cms.headers['x-feapi-token']
    # pass to getAlerts to use in POST to CMS
    ackAlerts(token)

def ackAlerts(token):
    parser = argparse.ArgumentParser(
        description='Requests a triage acquisition')

    parser.add_argument('-uuid', help='UUID String of Alert Ex: f907b2c6-7d3d-4f83-89d0-8bcb12ea56cb ', required=True)
    parser.add_argument('-type', help='Alert Type Ex: Malware Object', required=True)

    args = parser.parse_args(sys.argv[1:])

    if (args.uuid and args.type):
        r = requests.post(ackurl+sys.argv[2], verify=False, headers = \
            {"X-FeApi-Token" : token,'Accept' : 'application/json'}, json = \
            {"annotation" : "Acknowledged by Python","alertType" : sys.argv[4]})

        print(r.url, r.request.headers, r.request.body)
        print(r.status_code, r.reason, r.request, r.request.body)
    else:
        print('Too few arguments, need -uuid and -type')
        exit(1)

cmsauth(user,pwd)

