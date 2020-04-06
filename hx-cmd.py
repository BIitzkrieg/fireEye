#!/usr/bin/env python
# coding=utf-8

# #######################################################
# FireEye HX command-line utility
# Henrik Olsson, henrik.olsson@fireeye.com
# Modifed by Andrew Danis, Added containstatus, containstop, standard and comprehensive acquisition functions
#
# Usage examples:
# python hx-cmd.py triage -host VICTIM-1 -t "2016-12-16 04:00:00"
# python hx-cmd.py lr -host VICTIM-1 -sc "my_script.xml"
# python hx-cmd.py simpleioc -n "Bad URL" -t execution -k "urlMonitorEvent/requestUrl" -y text -o contains -m "evil.com"
# python hx-cmd.py fileaq -host VICTIM-1 -fp "C:\Windows\calc.exe" -m API
# python hx-cmd.py iocsearch -hostset 9 -f "File Name" -o "equals" -v "hosts"
# python hx-cmd.py openiocsearch -hostset 9 -i "/path/to/file.ioc"
# python hx-cmd.py containreq -host VICTIM-1
# python hx-cmd.py containstatus -host VICTIM-1
# python hx-cmd.py containstop -host VICTIM-1
# python hx-cmd.py stanacq -host VICTIM-1
# python hx-cmd.py compacq -host VICTIM-1

#########################################################

import argparse
import sys
import ntpath
import json
from hx_lib import *
import ssl

# HX Configuration settings
hx_host = ""
hx_port = "3000"
hx_user = ""
hx_pass = ""

hx_api_object = HXAPI(hx_host, hx_port=hx_port)


class hxcmd(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='FireEye HX command-line utility',
            usage='''\thx-cmd.py <command> [<args>]

List of commands:
   \tfileaq         Request file acqusition
   \ttriage         Request Triage acquisition
   \tsimpleioc      Add a simple IOC
   \tlr             Run a live response script (Requires HX Power license)
   \topeniocsearch  Run an OpenIOC Enterprise Search (Requires HX Power license)
   \tiocsearch      Run a single token Enterprise Search
   \tcontainreq     Containment request for a host
   \tcontainapp     Containment request for a host (Requires API admin account)
   \tcontainstatus	Containment status request for a host
   \tcontainstop	Cancels a containment request or removes a host from quarantine
   \tstanacq        Requests a standard investigative data acquisition
   \tcompacq        Requests a comprehensive investigative data acquisition
''')
        parser.add_argument('command', help='Subcommand to run')
        args = parser.parse_args(sys.argv[1:2])

        if not hasattr(self, args.command):
            print('Unrecognized command')
            parser.print_help()
            exit(1)

        getattr(self, args.command)()

    # File Acquisition
    def fileaq(self):
        parser = argparse.ArgumentParser(
            description='Requests a file acquisition')

        parser.add_argument('-host', help='Hostname', metavar='hostname', required=True)
        parser.add_argument('-fp', help='Filepath - must be in "quotes"', metavar='filepath', required=True)
        parser.add_argument('-m', help='Mode', metavar='RAW/API', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host and args.fp and args.m):

            path, filename = ntpath.split(args.fp)

            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']

                    if args.m in ("API", "api"):
                        mode = True
                    elif args.m in ("RAW", "raw"):
                        mode = False
                    else:
                        mode = True

                    (ret, response_code, result) = hx_api_object.restAcquireFile(agentId, path, filename, mode)
                    if ret:

                        print("\t# Identified host:\t\t\t" + hostdata['data']['entries'][0]['hostname'])
                        print("\t# Installed OS:\t\t\t\t" + hostdata['data']['entries'][0]['os'][
                            'product_name'] + ", " + str(hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                              hostdata['data']['entries'][0]['os']['bitness'])

                        print("\t# New file acquisition request with ID:\t" + str(result['data']['_id']))
                        print("\t# Filepath:\t\t\t\t" + str(result['data']['req_path']))
                        print("\t# Filename:\t\t\t\t" + str(result['data']['req_filename']))
                        print("\t# Acqusition mode::\t\t\t" + args.m)
                        print("\t# Message from FireEye HX:\t\t" + result['message'])
                    else:
                        print("Unable to run acquisition query")
                        print(result)

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\t\tSuccessfully released token")

        else:
            print('Too few arguments, need -host, -fp and -m')
            exit(1)

    # Triage acquisition
    def triage(self):
        parser = argparse.ArgumentParser(
            description='Requests a triage acquisition')

        parser.add_argument('-host', help='Hostname', required=True)
        parser.add_argument('-t', help='Timestamp', required=False, metavar='timestamp')

        args = parser.parse_args(sys.argv[2:])

        if (args.host):
            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']

                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])

                    if (args.t):
                        (ret, response_code, result) = hx_api_object.restAcquireTriage(agentId, args.t)
                    else:
                        (ret, response_code, result) = hx_api_object.restAcquireTriage(agentId)

                    if ret:
                        print("\t# New triage request with ID:\t" + str(result['data']['_id']))

                        if (args.t):
                            print("\t# Triage type:\t\t\tAround timestamp")
                            print("\t# Triage timestamp:\t\t" + str(result['data']['req_timestamp']))
                        else:
                            print("\t# Triage type:\t\t\tStandard")

                        print("\t# Message from FireEye HX:\t" + result['message'])

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")
        else:
            print('Too few arguments, need -host for standard triage and -host and -t for "around timestamp"')
            exit(1)

    # Create a simple ioc with one condition
    def simpleioc(self):
        parser = argparse.ArgumentParser(
            description='Creates an indicator with one condition')

        parser.add_argument('-p', help='Platforms (all or comma separated list)', required=True)
        parser.add_argument('-n', help='Indicator name', required=True)
        parser.add_argument('-t', help='Indicator type (presence/execution)', required=True)
        parser.add_argument('-k', help='Token', required=True)
        parser.add_argument('-y', help='Type (md5/text/integer/range)', required=True)
        parser.add_argument('-o', help='Operator (equal/contains/starts-with/ends-with/matches)', required=True)
        parser.add_argument('-m', help='Matching value', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.n and args.t and args.k and args.y and args.o and args.m and args.p):

            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\tSuccessful")

                data = "{\"tests\":[{\"token\":\"" + args.k + "\",\"type\":\"" + args.y + "\",\"operator\":\"" + args.o + "\",\"value\":\"" + args.m + "\"}]}"
                category = "custom"

                if args.p == "all":
                    myplatforms = ['win', 'osx']
                else:
                    myplatforms = args.p.split(",")

                (ret, response_code, response_data) = hx_api_object.restAddIndicator(hx_user, args.n, myplatforms,
                                                                                     category)
                if ret:
                    (ret, response_code, result) = hx_api_object.restAddCondition(category, iocURI, args.t, data)
                    if ret:
                        print("\t# IOC Name:\t\t" + args.n)
                        print("\t# IOC type:\t\t" + args.t)
                        print("\t# Message from HX:\t" + result['message'])
                        print("\t# JSON:\t\t\t" + json.dumps(result['data']['tests']))

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\tSuccessfully released token")
        else:
            print("Too few arguments")
            exit(1)

    # Submit a new live response request
    def lr(self):
        parser = argparse.ArgumentParser(
            description='Submits a live response request for a named endpoint')

        parser.add_argument('-host', help='Hostname', metavar='hostname', required=True)
        parser.add_argument('-n', help='Script name', required=True)
        parser.add_argument('-sc', help='Script filename', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host and args.sc and args.n):

            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']

                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])
                    print("\t# Script Name:\t\t\t" + args.n)

                    sfile = open(args.sc, 'r')
                    sc = sfile.read()
                    sfile.close()

                    (ret, response_code, result) = hx_api_object.restNewAcquisition(agentId, args.n, str.encode(sc))
                    if ret:
                        print("\t# Message from FireEye HX:\t" + result['message'])

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")
        else:
            print("Too few arguments")
            exit(1)

    def openiocsearch(self):
        parser = argparse.ArgumentParser(
            description='Submits a new OpenIOC enterprise search')

        parser.add_argument('-hostset', help='Hostset', metavar='hostset', required=True)
        parser.add_argument('-i', help='OpenIOC to use', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.hostset and args.i):

            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\tSuccessful")

                sfile = open(args.i, 'r')
                ioc = sfile.read()
                sfile.close()

                (ret, response_code, result) = hx_api_object.restSubmitSweep(str.encode(ioc), args.hostset)
                if ret:
                    print("\t# Matched host-set:\t" + result['data']['host_set']['name'])
                    print("\t# State:\t\t" + result['data']['state'])
                    print("\t# Search type:\t\t" + result['data']['settings']['search_type'])
                    print("\t# Exhaustive:\t\t" + str(result['data']['settings']['exhaustive']))
                    print("\t# Hosts:\t\t" + str(result['data']['stats']['hosts']))

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\tSuccessfully released token")
        else:
            print("Too few arguments")
            exit(1)

    # Create a simple enterprise search with one condition
    def iocsearch(self):
        parser = argparse.ArgumentParser(
            description='Creates an enterprise search with one condition')

        parser.add_argument('-hostset', help='Hostset', metavar='hostset', required=True)
        parser.add_argument('-f', help='Field', required=True)
        parser.add_argument('-o', help='Operator (equal/contains/starts-with/ends-with/matches)', required=True)
        parser.add_argument('-v', help='Matching value', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.hostset and args.f and args.o and args.v):

            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\tSuccessful")

                query = ([{"field": args.f, "operator": args.o, "value": args.v}])

                (ret, response_code, result) = hx_api_object.restSubmitSearch(query, args.hostset)
                if ret:
                    print("\t# Matched host-set:\t" + result['data']['host_set']['name'])
                    print("\t# State:\t\t" + result['data']['state'])
                    print("\t# Search type:\t\t" + result['data']['settings']['search_type'])
                    print("\t# Exhaustive:\t\t" + str(result['data']['settings']['exhaustive']))
                    print("\t# Hosts:\t\t" + str(result['data']['stats']['hosts']))

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\tSuccessfully released token")
        else:
            print("Too few arguments")
            exit(1)

    def containreq(self):
        parser = argparse.ArgumentParser(
            description='Submits a containment request')

        parser.add_argument('-host', help='Hostname or IP', metavar='host', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host):
            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']
                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])

                    (ret, response_code, result) = hx_api_object.restRequestContainment(agentId)
                    if ret:
                        print("\t# HX Response:\t\t\t" + hostdata['message'])

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")

        else:
            print("Too few arguments")
            exit(1)

    def containapp(self):
        parser = argparse.ArgumentParser(
            description='Submits a containment approval (requires api_admin role)')

        parser.add_argument('-host', help='Hostname or IP', metavar='host', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host):
            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']
                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])

                    (ret, response_code, result) = hx_api_object.restApproveContainment(agentId)
                    if ret:
                        print("\t# HX Response:\t\t\t" + hostdata['message'])
                        # Test to see HX json response
                        #print(response_code, result)
                        if response_code == 201:
                            print("\t# Host Contained:\t" + "Yes")
                        elif response_code == 404:
                            print("\t#Agent ID does not exist")
                        elif response_code == 405:
                            print("\t#Linux host, not supported")
                        elif response_code == 422:
                            print("\t#Unsuccessful, host not released from containment, unknown or invalid fields in input")
                        else:
                            print("\t#Other error:" + "response code: " + response_code + "Result: " + result)

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")

        else:
            print("Too few arguments")
            exit(1)

    def containstatus(self):
        parser = argparse.ArgumentParser(
            description='Gets containment status')

        parser.add_argument('-host', help='Hostname or IP', metavar='host', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host):
            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    # test to see HX json result
                    # print(hostdata)
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']
                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])

                    (ret, response_code, result) = hx_api_object.restGetContainmentStatus(agentId)
                    if ret:
                        # test to see HX json result
                        #print(result)
                        print("\t# HX Response:\t\t\t" + hostdata['message'])
                        try:
                            if result['data']['queued'] is True:
                                print("\t# Containment Requested:\t" + "Yes")
                            elif result['data']['queued'] is False:
                                print("\t# Containment Requested:\t" + "No")
                        except:
                            print("Error")
                        try:
                            if result['data']['state'] == "contained":
                                print("\t# Host quarantined:\t\t" + "Yes")
                            if result['data']['state'] == "uncontaining":
                                print("\t# Processing Uncontainment:\t" + "Yes")
                            elif result['data']['state'] == "normal":
                                print("\t# Host quarantined:\t\t" + "No")
                        except:
                            print("Error")

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")

        else:
            print("Too few arguments")
            exit(1)

    def containstop(self):
        parser = argparse.ArgumentParser(
            description='Stops containment requests/quarantine ')

        parser.add_argument('-host', help='Hostname or IP', metavar='host', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host):
            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    # test to see HX json result
                    # print(hostdata)
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']
                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])

                    (ret, response_code, result) = hx_api_object.restRemoveContainment(agentId)
                    if ret:
                        # test to see HX json result
                        # print(result)
                        if response_code == 204:
                            print("\t# Released from quarantine:\t" + "Yes")
                        elif response_code == 404:
                            print("\t# Agent ID does not exist")
                        elif response_code == 405:
                            print("\t# Linux host, not supported")
                        elif response_code == 409:
                            print("\t# Unsuccessful, host not released from containment")
                        else:
                            print("\t# Other error:" + "response code: " + response_code + "Result: " + result)

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")

        else:
            print("Too few arguments")
            exit(1)

    def stanacq(self):
        parser = argparse.ArgumentParser(
            description='Pulls standard investigation details ')

        parser.add_argument('-host', help='Hostname or IP', metavar='host', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host):
            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    # test to see HX json result
                    # print(hostdata)
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']
                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])

                    (ret, response_code, result) = hx_api_object.restNewAcquisition(agentId, script="6d4cdc1e72ba17bbf9788b6142eae43d45f473ee")
                    if ret:
                        # test to see HX json result
                        # print(result)
                        if response_code == 201:
                            print("\t# Standard Investigative Details Acquisition Started:\t" + "Yes")
                        elif response_code == 404:
                            print("\t# Agent ID does not exist")
                        elif response_code == 422:
                            print("\t# Unsuccessful, invalid fields included in input")
                        else:
                            print("\t# Other error:" + "response code: " + response_code + "Result: " + result)

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")

        else:
            print("Too few arguments")
            exit(1)

    def compacq(self):
        parser = argparse.ArgumentParser(
            description='Pulls Comprehensive investigation details ')

        parser.add_argument('-host', help='Hostname or IP', metavar='host', required=True)

        args = parser.parse_args(sys.argv[2:])

        if (args.host):
            (ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
            if ret:
                print("\t# Authentication:\t\tSuccessful")

                (ret, response_code, hostdata) = hx_api_object.restFindHostsBySearchString(args.host)
                if ret:
                    # test to see HX json result
                    # print(hostdata)
                    if len(hostdata['data']['entries']) == 0:
                        print("No matching host")
                        exit(1)

                    agentId = hostdata['data']['entries'][0]['_id']
                    print("\t# Identified host:\t\t" + hostdata['data']['entries'][0]['hostname'])
                    print("\t# Installed OS:\t\t\t" + hostdata['data']['entries'][0]['os']['product_name'] + ", " + str(
                        hostdata['data']['entries'][0]['os']['patch_level']) + ", " +
                          hostdata['data']['entries'][0]['os']['bitness'])

                    (ret, response_code, result) = hx_api_object.restNewAcquisition(agentId, script="b36ebec6d9fa0411c4d6f68d01e4d16769a0f990")
                    if ret:
                        # test to see HX json result
                        # print(result)
                        if response_code == 201:
                            print("\t# Comprehensive Investigative Details Acquisition Started:\t" + "Yes")
                        elif response_code == 404:
                            print("\t# Agent ID does not exist")
                        elif response_code == 422:
                            print("\t# Unsuccessful, invalid fields included in input")
                        else:
                            print("\t# Other error:" + "response code: " + response_code + "Result: " + result)

                (ret, response_code, response_data) = hx_api_object.restLogout()
                if ret:
                    print("\t# Authentication:\t\tSuccessfully released token")

        else:
            print("Too few arguments")
            exit(1)

if __name__ == '__main__':
    hxcmd()
