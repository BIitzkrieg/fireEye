#!/opt/jupyter/bin/python
# Andrew Danis
# Simple script to feed a list of hosts to modified hx-cmd script by FireEye to preform bulk actions on a list of hosts.
import os
import subprocess


def validInput(string):
    if (string == "1" or string == "2" or string == "3" or string == "4" or string == "5" or string == "6" or string == "7"):
        return True
    else:
        return False

def mainMenu():
    print("######## Main Menu ########")
    print()
    #print("[ 1 ]  File Acquisition for a list of hosts")
    print("[ 1 ]  Acquire Triage for a list of hosts")
    print("[ 2 ]  Contain a list of hosts")
    print("[ 3 ]  Get Containment status for a list of hosts")
    print("[ 4 ]  Cancels a containment request or removes a host from quarantine")
    print("[ 5 ]  Pull a Standard Investigation Acquisition for a list of hosts")
    print("[ 6 ]  Pull a Comprehensive Investigation Acquisition for a list of hosts")
    print("[ 7 ]  Exit")
    print()
    userInput = input("Pick a function to run: ")
    while not validInput(userInput):
        userInput = input("Please enter a valid input. [ 1-7 ] ")
    userInput = int(userInput)
    # Triage Acq
    if userInput == 1:
        print()
        runCMD(userInput)
        print()
    # Contain req
    if userInput == 2:
        print()
        runCMD(userInput)
    # Contain status
    if userInput == 3:
        print()
        runCMD(userInput)
        print()
    # Cancels containment
    if userInput == 4:
        print()
        runCMD(userInput)
        print()
    # Standard Investigation Acquisition
    if userInput == 5:
        print()
        runCMD(userInput)
        print()
    # Comprehensive Investigation Acquisition
    if userInput == 6:
        print()
        runCMD(userInput)
        print()
    #Exit Program
    if userInput == 7:
        return False



def runCMD(userInput):
    count = 0
    f = open("hosts.txt")
    contents = f.read()
    file_as_list = contents.splitlines()
    for host in file_as_list:
        if userInput == 1:
            print("Pulling Triage for Hosts")
            print()
            command = subprocess.Popen("/opt/jupyter/bin/python hx-cmd.py triage -host "+ host, shell=True, stdout=subprocess.PIPE).stdout
            output = command.read()
            print(output.decode())
        if userInput == 2:
            print("Containing Hosts")
            print()
            command = subprocess.Popen("/opt/jupyter/bin/python hx-cmd.py containapp -host "+ host, shell=True,stdout=subprocess.PIPE).stdout
            output = command.read()
            print(output.decode())
        if userInput == 3:
            print("Getting Containment Status of Hosts")
            print()
            command = subprocess.Popen("/opt/jupyter/bin/python hx-cmd.py containstatus -host " + host, shell=True,stdout=subprocess.PIPE).stdout
            output = command.read()
            print(output.decode())
        if userInput == 4:
            print("Stopping Containment of Hosts")
            print()
            command = subprocess.Popen("/opt/jupyter/bin/python hx-cmd.py containstop -host " + host, shell=True,stdout=subprocess.PIPE).stdout
            output = command.read()
            print(output.decode())
        if userInput == 5:
            print("Getting Standard Acquisition for Hosts")
            print()
            command = subprocess.Popen("/opt/jupyter/bin/python hx-cmd.py stanacq -host " + host, shell=True,stdout=subprocess.PIPE).stdout
            output = command.read()
            print(output.decode())
        if userInput == 6:
            print("Getting Comprehensive Acquisition for Hosts")
            print()
            command = subprocess.Popen("/opt/jupyter/bin/python hx-cmd.py compacq -host " + host, shell=True,stdout=subprocess.PIPE).stdout
            output = command.read()
            print(output.decode())
        count += 1
        print()
        print("Host: " + host + " done")
        print()
    print(str(count)+ " hosts done")
    print()
    mainMenu()

running = True
while running == True:

    running = mainMenu()
