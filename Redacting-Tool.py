# Copyright (c) {{current_year}} Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

# Title
# Redacting Tool
#
# Language
# Python 3.5
#
# Description
# This tool will remove all IP address, MAC addresses, Hostnames, Domains, Username/Passwords from
# various output from Cisco Devices.
#
# Contacts
# Phil Bridges - phbridge@cisco.com
#
# EULA
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges
# with a variety of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and
# arrangements. Until provision of alcohol or baked goodies your on your own but there is no rocket science
# involved so don't panic too much. To accept this EULA you must include the correct flag when running the script.
# If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any
# liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held
# responsible for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit from
# this script but will not assume any liability. Other than the boring stuff please enjoy and plagiarise as you
# like (as I have no ways to stop you) but common curacy says to credit me in some way
# [see above comments on Beer, Wine, Steak and Greggs.].
#
# Version Control               Comments
# Version 0.1 Date 14/06/18     Inital draft
# Version 0.2 Date 26/06/18     Working for IPv4
# Version 0.3 Date 26/06/18     Working for IPv6
# Version 0.4 Date 26/06/18     Working for hostnames
# Version 0.5 Date 26/06/18     Working for domains
# Version 0.6 Date 26/06/18     Working for usernames
# Version 0.7 Date 26/06/18     Working for NoDictrionary
# Version 0.8 Date 26/06/18     Working for MAC addresses
# Version 1.0 Date 27/06/18     Tieded up code All working
#
#
#
# Version 6.9 Date xx/xx/xx     Took over world and actuially got paid for value added work....If your reading this
#                               approach me on linkedin for details of weekend "daily" rate :-)
# Version 7.0 Date xx/xx/xx     Note to the Gaffer - if your reading this then the above line is a joke only :-)
#
# ToDo *******************TO DO*********************
# 1.0 Implement Full IP masking (4 octet)                   DONE
# 1.1 Implement Partial IP masking (first 3 octet)          DONE
# 1.2 Implement Partial IP masking (first 2 octet)          DONE
# 1.3 Implement IPv6 masking                                DONE
# 2.0 Implement hostname masking                            DONE
# 3.0 Implement domain masking                              DONE - EDITED to include both domain name and domain-name
# 4.0 Implement MAC address masking                         DONE
# 5.0 Table masking                                         DONE
# 6.0 Implement Username/Password masking                   DONE
# 7.0 Implement Wget Counter                                TO DO When time Permits
# 8.0 Implement wipeout masking                             DONE
#

import argparse                 # needed for the nice menus and variable checking
from datetime import datetime   # needed for the datetime for filename
import re                       # Regular expression usage for finding things
import random                   # used for random IP address generation


def parse_all_arguments():
    parser = argparse.ArgumentParser(description='process input')
    parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False,
                        help="Marking this flag accepts EULA embedded withing the script")
    parser.add_argument("-i", "--inputfile", required=True, type=argparse.FileType('r', encoding='UTF-8'),
                        help="input file that needs to be redacted")
    parser.add_argument("-o", "--outputfile", required=False,
                        help="output file that needs to be redacted")
    parser.add_argument("-v", "--verbose", action='store_true', default=False,
                        help="increase output verbosity", )
    parser.add_argument("-1v4", "--IPv4_1", action='store_true', default=False,
                        help="use this flag to modify IP addresses 1st octet only")
    parser.add_argument("-2v4", "--IPv4_2", action='store_true', default=False,
                        help="use this flag to modify IP addresses 1st + 2nd octet only")
    parser.add_argument("-3v4", "--IPv4_3", action='store_true', default=False,
                        help="use this flag to modify IP addresses 1st + 2nd + 3rd octet only")
    parser.add_argument("-4v4", "--IPv4_4", action='store_true', default=False,
                        help="use this flag to modify IP addresses whole IP address")
    parser.add_argument("-1v6", "--IPv6_1", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st colon")
    parser.add_argument("-2v6", "--IPv6_2", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st + 2nd colon")
    parser.add_argument("-3v6", "--IPv6_3", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st, 2nd + 3rd colon")
    parser.add_argument("-4v6", "--IPv6_4", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st, 2nd, 3rd + 4th colon")
    parser.add_argument("-5v6", "--IPv6_5", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st, 2nd, 3rd, 4th + 5th colon")
    parser.add_argument("-6v6", "--IPv6_6", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st, 2nd, 3rd, 4th, 5th + 6th colon")
    parser.add_argument("-7v6", "--IPv6_7", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st, 2nd, 3rd, 4th, 5th, 6th + 7th colon")
    parser.add_argument("-8v6", "--IPv6_8", action='store_true', default=False,
                        help="use this flag to modify IPv6 addresses 1st, 2nd, 3rd, 4th, 5th, 6th, 7th + 8th colon")
    parser.add_argument("-NoDict", "--nodictionary", action='store_true', default=False,
                        help="Use the NoDict flag if you do not want to use dictionary and use <--field name--> markers")
    parser.add_argument("-hostname", "--hostname", action='store_true', default=False,
                        help="use this flag to modify all hostnames")
    parser.add_argument("-d", "--domain", action='store_true', default=False,
                        help="use this flag to modify all domains")
    parser.add_argument("-m", "--mac", action='store_true', default=False,
                        help="use this flag to modify all mac addresses")
    parser.add_argument("-u", "--username", action='store_true', default=False,
                        help="use this flag to modify all credentials")
    parser.add_argument("-c", "--certificates", action='store_true', default=False,
                        help="use this flag to modify all certificates NOT IMPLEMENTED YET")
    args = parser.parse_args()

    if args.acceptedeula == False:
        print("""you need to accept the EULA agreement which is as follows:-
    # EULA
    # This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges 
    # with a variety of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and 
    # arrangements. Until provision of alcohol or baked goodies your on your own but there is no rocket science 
    # involved so don't panic too much. To accept this EULA you must include the correct flag when running the script. 
    # If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any 
    # liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held 
    # responsible for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit from 
    # this script but will not assume any liability. Other than the boring stuff please enjoy and plagiarise as you 
    # like (as I have no ways to stop you) but common curacy says to credit me in some way 
    # [see above comments on Beer, Wine, Steak and Greggs.].
    
    # To accept the EULA please run with the -ACCEPTEULA flag
        """)
        quit()

    if args.verbose:
        print("-v Verbose flag set printing extended ouput")
        print("seed file loaded is ", str(args.inputfile.name))
    print(str(datetime.now()) + "     " + "Arguments and files loaded")
    if args.verbose:
        print(str(args.acceptedeula))
        print(str(args.verbose))
        print(str(args.IPv4_1))
        print(str(args.IPv4_2))
        print(str(args.IPv4_3))
        print(str(args.IPv4_4))
        print(str(args.IPv6_1))
        print(str(args.IPv6_2))
        print(str(args.IPv6_3))
        print(str(args.IPv6_4))
        print(str(args.IPv6_5))
        print(str(args.IPv6_6))
        print(str(args.IPv6_7))
        print(str(args.IPv6_8))
        print(str(args.hostname))
        print(str(args.domain))
        print(str(args.mac))
        print(str(args.username))
        print(str(args.certificates))
        print(str(args.outputfile))
    return args


def create_logfile():
    try:
        output_filename = str(datetime.now()) + "-Redacting-Tool"
        output_log = open(str(output_filename) + ".text", 'a+')
        output_log.write(str(datetime.now()) + "     " + "log file created sucessfully file name should be " +
                         str(output_filename) + "\n")
    except:
        print("something went bad opening/creating file for writing")
        print("Unexpected error:", sys.exc_info()[0])
        quit()
    return output_log


def create_output_file():
    try:
        if args.outputfile is None:
            output_file_name = str(str(datetime.now()) + "-OutputFile")
            print(str(datetime.now()) + "     " + "output file created with name " + str(output_file_name))
        else:
            output_file_name = str(args.outputfile)
            print(str(datetime.now()) + "     " + "output file created with name " + str(output_file_name))
        output_file = open(str(output_file_name) + ".text", 'a+')
        print(str(datetime.now()) + "     " + "output file created and opened")
    except:
        print("something went bad opening/creating output file for writing")
        print("Unexpected error:", sys.exc_info()[0])
        quit()
    return output_file


def write_kickoff_debugging():
    if args.verbose:
        print(str(datetime.now()) + "     " + "Arguments and files loaded")
        output_log.write(str(datetime.now()) + "     " + "-v Verbose flag set printing extended ouput" + "\n")

    output_log.write(str(datetime.now()) + "     " + "Arguments and files loaded" + "\n")
    output_log.write(str(datetime.now()) + "     " + "verbose flag is " + str(args.verbose) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP1 flag is" + str(args.IPv4_1) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP2 flag is" + str(args.IPv4_2) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP3 flag is" + str(args.IPv4_3) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP4 flag is" + str(args.IPv4_4) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP1 flag is" + str(args.IPv6_1) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP2 flag is" + str(args.IPv6_2) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP3 flag is" + str(args.IPv6_3) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP4 flag is" + str(args.IPv6_4) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP1 flag is" + str(args.IPv6_5) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP2 flag is" + str(args.IPv6_6) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP3 flag is" + str(args.IPv6_7) + "\n")
    output_log.write(str(datetime.now()) + "     " + "IP4 flag is" + str(args.IPv6_8) + "\n")
    output_log.write(str(datetime.now()) + "     " + "hostname flag is" + str(args.hostname) + "\n")
    output_log.write(str(datetime.now()) + "     " + "domain flag is" + str(args.domain) + "\n")
    output_log.write(str(datetime.now()) + "     " + "mac flag is" + str(args.mac) + "\n")
    output_log.write(str(datetime.now()) + "     " + "username flag is" + str(args.username) + "\n")
    output_log.write(str(datetime.now()) + "     " + "certificates flag is" + str(args.certificates) + "\n")
    output_log.write(str(datetime.now()) + "     " + "inputfile is" + str(args.inputfile) + "\n")
    return output_log


def open_input_file():
    #
    # NOW LOAD THE INPUT FILE
    #
    try:
        input_file = open(args.inputfile.name, "r", buffering=16777216, encoding='latin-1')
        output_log.write(str(datetime.now()) + "     " + "input file opened" + "\n")
    except:
        print(str(datetime.now()) + "     " + "error opening input file")
        output_log.write(str(datetime.now()) + "     " + "error opening input file" + "\n")
    return input_file

args = parse_all_arguments()
output_log = create_logfile()
output_file = create_output_file()
write_kickoff_debugging()
input_file = open_input_file()

def scope_ipv4_addresses():
    ipv4_octets_to_replace = 0
    if args.IPv4_1:
        ipv4_octets_to_replace = 1
    elif args.IPv4_2:
        ipv4_octets_to_replace = 2
    elif args.IPv4_3:
        ipv4_octets_to_replace = 3
    elif args.IPv4_4:
        ipv4_octets_to_replace = 4
    elif ipv4_octets_to_replace == 0:
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
    return ipv4_octets_to_replace
ipv4_octets_to_replace = scope_ipv4_addresses()


def scope_ipv6_addresses():
    ipv6_octets_to_replace = 0
    if args.IPv6_1:
        ipv6_octets_to_replace = 1
    elif args.IPv6_2:
        ipv6_octets_to_replace = 2
    elif args.IPv6_3:
        ipv6_octets_to_replace = 3
    elif args.IPv6_4:
        ipv6_octets_to_replace = 4
    elif args.IPv6_5:
        ipv6_octets_to_replace = 5
    elif args.IPv6_6:
        ipv6_octets_to_replace = 6
    elif args.IPv6_7:
        ipv6_octets_to_replace = 7
    elif args.IPv6_8:
        ipv6_octets_to_replace = 8
    elif ipv6_octets_to_replace == 0:
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########")
        print(str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
        output_log.write(str(
            datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
    return ipv6_octets_to_replace
ipv6_octets_to_replace = scope_ipv6_addresses()


def compile_regex():
    #
    # Find All things to replace
    #

    ipv4_regex = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
    ipv6_regex = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'                              
                            '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
                            '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
                            '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
                            '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                            '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
                            '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
                            '([0-9a-fA-F]{1,4}:){1,7}:)')
    hostname_regex = re.compile(r'^hostname\s*(.*)')
    domain_regex = re.compile(r'^ip domain name\s*(.*)')
    domain_name_regex = re.compile(r'^ip domain-name\s*(.*)')
    mac_regex = re.compile('(([0-9a-fA-F]{4}[\.]){2}[0-9a-fA-F]{4})')
    username_regex = re.compile(r'^username\s*(.*)')
    return ipv4_regex, ipv6_regex, hostname_regex, domain_regex, domain_name_regex, mac_regex, username_regex

ipv4_regex, ipv6_regex, hostname_regex, domain_regex, domain_name_regex, mac_regex, username_regex = compile_regex()

def process_input_for_dictionary():
    ipv4_address_list_raw = []
    ipv6_address_list_raw = []
    hostname_list_raw = []
    domain_list_raw = []
    mac_address_list_raw = []
    username_list_raw = []
    for line in input_file:
        #print(str(line))
        ipv4_working_line = []
        ipv6_working_line = []
        hostname_working_line = []
        domain_working_line = []
        mac_working_line = []
        username_working_line = []
        ipv4_working_line = ipv4_regex.findall(line)
        ipv6_working_line = ipv6_regex.findall(line)
        hostname_working_line = hostname_regex.findall(line)
        domain_working_line = domain_regex.findall(line)
        domain_name_working_line = domain_name_regex.findall(line)
        mac_working_line = mac_regex.findall(line)
        username_working_line = domain_regex.findall(line)
        if not ipv4_working_line == []:
            for i in ipv4_working_line:
                ipv4_address_list_raw.append(i)
        if not ipv6_working_line == []:
            for i in ipv6_working_line:
                ipv6_address_list_raw.append(i[0])
        if not hostname_working_line == []:
            for i in hostname_working_line:
                hostname_list_raw.append(i)
        if not domain_working_line == []:
            for i in domain_working_line:
                domain_list_raw.append(i)
        if not domain_name_working_line == []:
            for i in domain_name_working_line:
                domain_list_raw.append(i)
        if not mac_working_line == []:
            for i in mac_working_line:
                mac_address_list_raw.append(i[0])
        if not username_working_line == []:
            for i in username_working_line:
                username_list_raw.append(i)
    return ipv4_address_list_raw, ipv6_address_list_raw, hostname_list_raw, domain_list_raw, mac_address_list_raw, username_list_raw,

ipv4_address_list_raw, ipv6_address_list_raw, hostname_list_raw, domain_list_raw, mac_address_list_raw, username_list_raw, = process_input_for_dictionary()


def print_verbose_debuging():
    #
    # Print details if verbose selected
    #
    output_log.write(
                str(datetime.now()) + "     " + "here is the RAW IPv4 address list" + str(ipv4_address_list_raw) + "\n")
    output_log.write(
                str(datetime.now()) + "     " + "here is the RAW IPv6 address list" + str(ipv6_address_list_raw) + "\n")
    output_log.write(
                str(datetime.now()) + "     " + "here is the RAW hostname list" + str(hostname_list_raw) + "\n")
    output_log.write(
                str(datetime.now()) + "     " + "here is the RAW domain list" + str(domain_list_raw) + "\n")
    output_log.write(
                str(datetime.now()) + "     " + "here is the RAW mac address list" + str(mac_address_list_raw) + "\n")
    output_log.write(
                str(datetime.now()) + "     " + "here is the RAW username list" + str(username_list_raw) + "\n")
    # Print All IPv4 addresses
    #
    output_log.write(str(datetime.now()) + "     " + "here is the RAW IPv4 address list length is " + str(len(ipv4_address_list_raw)) + "\n")
    print(str(datetime.now()) + "     " + str(len(ipv4_address_list_raw)) + " IPv4 addresses found")
    #
    # Print All IPv6 addresses
    #
    output_log.write(str(datetime.now()) + "     " + "here is the RAW  IPv6address list length is " + str(len(ipv6_address_list_raw)) + "\n")
    print(str(datetime.now()) + "     " + str(len(ipv6_address_list_raw)) + " IPv6 addresses found")
    #
    # Print Hostname Stuff
    #
    output_log.write(str(datetime.now()) + "     " + "here is the RAW hostname list length is " + str(len(hostname_list_raw)) + "\n")
    print(str(datetime.now()) + "     " + str(len(hostname_list_raw)) + " hostname found")
    #
    # Print domain name stuff
    #
    output_log.write(str(datetime.now()) + "     " + "here is the RAW domain list length is " + str(len(domain_list_raw)) + "\n")
    print(str(datetime.now()) + "     " + str(len(hostname_list_raw)) + " domains found")
    #
    # Print mac address stuff
    #
    output_log.write(str(datetime.now()) + "     " + "here is the RAW mac address list length is " + str(len(mac_address_list_raw)) + "\n")
    print(str(datetime.now()) + "     " + str(len(mac_address_list_raw)) + " MAC addresses found")
    #
    # Print Username stuff
    #
    output_log.write(str(datetime.now()) + "     " + "here is the RAW username list length is " + str(len(username_list_raw)) + "\n")
    print(str(datetime.now()) + "     " + str(len(username_list_raw)) + " usernames found")
    return

if args.verbose:
    print_verbose_debuging()
#
# Unique things
#


def remove_duplicates(original_list):
    no_duplicate_list = []
    for i in original_list:
        if not i:
            continue
        if i not in no_duplicate_list:
            #if not i:   # checks for empty string (I hope)
            print(str(i))
            no_duplicate_list.append(i)
    return no_duplicate_list

ipv4_address_list = remove_duplicates(ipv4_address_list_raw)
ipv6_address_list = remove_duplicates(ipv6_address_list_raw)
hostname_list = remove_duplicates(hostname_list_raw)
domain_list = remove_duplicates(domain_list_raw)
mac_address_list = remove_duplicates(mac_address_list_raw)
username_list = remove_duplicates(username_list_raw)

if args.verbose:
    output_log.write(str(datetime.now()) + "     " + "here is the no dup list is " + str(ipv4_address_list) + "\n")
    output_log.write(str(datetime.now()) + "     " + "here is the no dup ipv6 list is " + str(ipv6_address_list) + "\n")
    output_log.write(str(datetime.now()) + "     " + "here is the no dup hostname list is " + str(hostname_list) + "\n")
    output_log.write(str(datetime.now()) + "     " + "here is the no dup domain list is " + str(domain_list) + "\n")
    output_log.write(str(datetime.now()) + "     " + "here is the no dup mac address list is " + str(mac_address_list) + "\n")
    output_log.write(str(datetime.now()) + "     " + "here is the no dup username list is " + str(username_list) + "\n")

output_log.write(str(datetime.now()) + "     " + "here is the Rno dup list length is " + str(len(ipv4_address_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(ipv4_address_list)) + " unique IP addresses found")
output_log.write(str(datetime.now()) + "     " + "here is the Rno dup ipv6 list length is " + str(len(ipv6_address_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(ipv6_address_list)) + " unique IPv6 addresses found")
output_log.write(str(datetime.now()) + "     " + "here is the Rno dup hostname list length is " + str(len(hostname_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(hostname_list)) + " unique hostname addresses found")
output_log.write(str(datetime.now()) + "     " + "here is the Rno dup domain list length is " + str(len(domain_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(domain_list)) + " unique domain addresses found")
output_log.write(str(datetime.now()) + "     " + "here is the Rno dup mac address list length is " + str(len(mac_address_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(mac_address_list)) + " unique mac addresses found")
output_log.write(str(datetime.now()) + "     " + "here is the Rno dup username list length is " + str(len(username_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(username_list)) + " unique username found")
#
# Build replacement dictionary
#
#

#
# Replacement Dictionary for IPv4
#
print(str(datetime.now()) + "     " + "replacing first " + str(ipv4_octets_to_replace) + " octets")
ipv4_replacement_dictionary = {}
ipv4_address_list_replacement = []

for i in ipv4_address_list:
    ipv4_origional_address = i.split(".")
    ipv4_masked_address = []

    for o in range(0, ipv4_octets_to_replace):
        ipv4_masked_address.append(random.randint(0, 255))
        if not o == 3:
            ipv4_masked_address.append(".")

    for p in range(4-ipv4_octets_to_replace, 0, -1):
        ipv4_masked_address.append(ipv4_origional_address[4-p])
        if not p == 1:
            ipv4_masked_address.append(".")

    ipv4_address_list_replacement.append(''.join(str(x) for x in ipv4_masked_address))
    if not args.nodictionary:
        ipv4_replacement_dictionary[i] = ''.join(str(x) for x in ipv4_masked_address)
    elif args.nodictionary:
        ipv4_replacement_dictionary[i] = "<--IPv4-Address-->"

output_log.write(str(datetime.now()) + "     " + "here is the replacement list is " + str(ipv4_address_list_replacement) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the replacement dictionary is " + str(ipv4_replacement_dictionary) + "\n")
print(str(datetime.now()) + "     " +"ipv6 dictionary created starting replacement for " + str(args.inputfile.name) + " file")
#
# Replacement Dictionary for IPv6
#
print(str(datetime.now()) + "     " +"replacing first " + str(ipv6_octets_to_replace) + " octets")
ipv6_replacement_dictionary = {}
ipv6_address_list_replacement = []
for i in ipv6_address_list:
    ipv6_origional_address = i.split(":")
    ipv6_masked_address = []
    #
    # Pad out addresses with ::
    #
    for o in range(0, 7):
        if len(ipv6_origional_address) == 8:
            if ipv6_origional_address[o] == '':
                ipv6_origional_address[o] = "0000"
        elif ipv6_origional_address[o] == '':
            ipv6_origional_address.insert(o, "0000")
    #
    # build fake address
    #
    for o in range(0, ipv6_octets_to_replace):
        ipv6_masked_address.append(''.join(str(random.choice("0123456789ABCDEF") + random.choice("0123456789ABCDEF") +
                                               random.choice("0123456789ABCDEF") + random.choice("0123456789ABCDEF"))))
        if not o == 7:
            ipv6_masked_address.append(":")
    for p in range(8-ipv6_octets_to_replace, 0, -1):
        ipv6_masked_address.append(ipv6_origional_address[8-p])
        if not p == 1:
            ipv6_masked_address.append(":")

    ipv6_address_list_replacement.append(''.join(str(x) for x in ipv6_masked_address))
    if not args.nodictionary:
        ipv6_replacement_dictionary[i] = ''.join(str(x) for x in ipv6_masked_address)
    elif args.nodictionary:
        ipv6_replacement_dictionary[i] = "<--IPv6-Address-->"

output_log.write(str(datetime.now()) + "     " + "here is the replacement list is " + str(ipv6_address_list_replacement) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the replacement dictionary is " + str(ipv6_replacement_dictionary) + "\n")
print(str(datetime.now()) + "     " +"ipv6 dictionary created starting replacement for " + str(args.inputfile.name) + " file")

#
# Replacement dictionary Hostname
#
print(str(datetime.now()) + "     " + "replacing hostname with <--HostName-->")
hostname_replacement_dictionary = {}
hostname_list_replacement = []

for i in hostname_list:
    hostname_replacement_dictionary[i] = "<--HostName-->"

output_log.write(str(datetime.now()) + "     " + "here is the replacement hostname list is " + str(hostname_list_replacement) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the replacement hostname dictionary is " + str(hostname_replacement_dictionary) + "\n")
print(str(datetime.now()) + "     " +"hostname dictionary created starting replacement for " + str(args.inputfile.name) + " file")
#
# Replacement dictionary Domain Name
#
print(str(datetime.now()) + "     " + "replacing domainname with <--DomainName-->")
domainname_replacement_dictionary = {}
domainname_list_replacement = []

for i in domain_list:
    domainname_replacement_dictionary[i] = "<--DomainName-->"

output_log.write(str(datetime.now()) + "     " + "here is the replacement domain list is " + str(domainname_list_replacement) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the replacement domain dictionary is " + str(domainname_replacement_dictionary) + "\n")
print(str(datetime.now()) + "     " +"domain dictionary created starting replacement for " + str(args.inputfile.name) + " file")
#
# Replacement dictionary Mac-Addresses
#

print(str(datetime.now()) + "     " + "replacing mac with <--MAC-Address-->")
mac_replacement_dictionary = {}
mac_list_replacement = []
#print(mac_address_list)
mac_regex_split = re.compile("[. :]")
for i in mac_address_list:
    mac_origional_address = mac_regex_split.split(i)
    mac_masked_address = []
    if len(mac_origional_address) == 6:         # for mac address in format 00:11:22:33:44:55
        for o in range(0, len(mac_origional_address)):
            mac_masked_address.append(''.join(str(random.choice("0123456789ABCDEF") + random.choice("0123456789ABCDEF"))))
            if o >= (len(mac_origional_address)-1):
                mac_masked_address.append(":")

    elif len(mac_origional_address) == 3:       # for mac address in format 0011.2233.4455
        for o in range(0, len(mac_origional_address)):
            mac_masked_address.append(''.join(str(random.choice("0123456789ABCDEF") + random.choice("0123456789ABCDEF") +
                                                   random.choice("0123456789ABCDEF") + random.choice("0123456789ABCDEF"))))
            if o <= (len(mac_origional_address)-2):
                mac_masked_address.append(".")
    if not args.nodictionary:
        mac_replacement_dictionary[i] = ''.join(str(x) for x in mac_masked_address)
    elif args.nodictionary:
        mac_replacement_dictionary[i] = "<--MAC-Address-->"

output_log.write(str(datetime.now()) + "     " + "here is the replacement mac address list is " + str(mac_list_replacement) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the replacement mac address dictionary is " + str(mac_replacement_dictionary) + "\n")
print(str(datetime.now()) + "     " +"mac address dictionary created starting replacement for " + str(args.inputfile.name) + " file")
#
#
# Replacement dictionary Username Name
#
print(str(datetime.now()) + "     " + "replacing usernames with <--UserName-->")
username_replacement_dictionary = {}
username_list_replacement = []

for i in username_list:
    username_replacement_dictionary[i] = "<--UserName-->"

output_log.write(str(datetime.now()) + "     " + "here is the replacement username list is " + str(username_list_replacement) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the replacement username dictionary is " + str(username_replacement_dictionary) + "\n")
print(str(datetime.now()) + "     " +"username dictionary created starting replacement for " + str(args.inputfile.name) + " file")
#
#
# NOW REPLACE STUFF
#
#
ipv4substrs = sorted(ipv4_replacement_dictionary, key=len, reverse=True)
ipv6substrs = sorted(ipv6_replacement_dictionary, key=len, reverse=True)
hostsubstrs = sorted(hostname_replacement_dictionary, key=len, reverse=True)
domainsubstrs = sorted(domainname_replacement_dictionary, key=len, reverse=True)
macaddsubstrs = sorted(mac_replacement_dictionary, key=len, reverse=True)
usernamesubstrs = sorted(username_replacement_dictionary, key=len, reverse=True)

ipv4regexp = re.compile('|'.join(map(re.escape, ipv4substrs)))
ipv6regexp = re.compile('|'.join(map(re.escape, ipv6substrs)))
hostnameregexp = re.compile('|'.join(map(re.escape, hostsubstrs)))
domainregexp = re.compile('|'.join(map(re.escape, domainsubstrs)))
macaddressregexp = re.compile('|'.join(map(re.escape, macaddsubstrs)))
usernameregexp = re.compile('|'.join(map(re.escape, usernamesubstrs)))

input_file.seek(0)
lines_done = 0
start_time = datetime.now()

for line in input_file:
    # There has got to be a nicer way of doing this at somepoint. Learning time needed. This adds 1 second for 30k lines
    if ipv4_octets_to_replace == 0:
        first_pass = line
    else:
        first_pass = str(ipv4regexp.sub(lambda match: ipv4_replacement_dictionary[match.group(0)], line))

    if ipv6_octets_to_replace == 0:
        second_pass = first_pass
    else:
        second_pass = (str(ipv6regexp.sub(lambda match: ipv6_replacement_dictionary[match.group(0)], first_pass)))

    if args.hostname:
        third_pass = (str(hostnameregexp.sub(lambda match: hostname_replacement_dictionary[match.group(0)], second_pass)))
    else:
        third_pass = second_pass

    if args.domain:
        fourth_pass = (str(domainregexp.sub(lambda match: domainname_replacement_dictionary[match.group(0)], third_pass)))
    else:
        fourth_pass = third_pass

    if args.mac:
        fith_pass = (str(macaddressregexp.sub(lambda match: mac_replacement_dictionary[match.group(0)], fourth_pass)))
    else:
        fith_pass = fourth_pass

    if args.username:
        output_file.write(str(usernameregexp.sub(lambda match: username_replacement_dictionary[match.group(0)], fith_pass)))
    else:
        output_file.write(str(fith_pass))

    lines_done += 1

end_time = datetime.now()

if ipv4_octets_to_replace == 0:
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
if ipv6_octets_to_replace == 0:
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv6")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv6")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv6")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv6")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv6")

output_log.write(str(datetime.now()) + "     " + "replaced  " + str(len(ipv4_address_list_raw)) +" IPv4 addresses" + "\n")
output_log.write(str(datetime.now()) + "     " + "replaced  " + str(len(ipv6_address_list_raw)) + " IPv6 addresses" + "\n")
output_log.write(str(datetime.now()) + "     " + "hidden in   " + str(lines_done) + " lines of output" + "\n")
output_log.write(str(datetime.now()) + "     " + "in " + str(end_time-start_time) + " seconds" + "\n")

print(str(datetime.now()) + "     " + "replaced " + str(len(ipv4_address_list_raw)) + " IPv4 adddress and ... ")
print(str(datetime.now()) + "     " + "replaced " + str(len(ipv6_address_list_raw)) + " IPv6 adddress and ... ")
print(str(datetime.now()) + "     " + "replaced " + str(len(hostname_list_raw)) + " hostnames and ... ")
print(str(datetime.now()) + "     " + "replaced " + str(len(domain_list_raw)) + " domain name and ... ")
print(str(datetime.now()) + "     " + "replaced " + str(len(mac_address_list_raw)) + " MAC adddress and ... ")
print(str(datetime.now()) + "     " + "replaced " + str(len(username_list_raw)) + " usernames all ... ")
print(str(datetime.now()) + "     " + "hidden in " + str(lines_done) + " lines of output ... ")
print(str(datetime.now()) + "     " + "and it only took me..... " + str(end_time-start_time) + " seconds")


def create_output_dictionary():
    #
    # If dictionary was used export dictionary to file now
    #
    try:
        output_dictionary_filename = str(datetime.now()) + "-Dictionary-Redacting-Tool"
        output_dictionary = open(str(output_dictionary_filename) + ".text", 'a+')
        for key, value in ipv4_replacement_dictionary.items():
            output_dictionary.write("Origional IPv4 Address " + str(key) + "     Was Replaced by " + str(value) + "\n")
        for key, value in ipv6_replacement_dictionary.items():
            output_dictionary.write("Origional IPv6 Address " + str(key) + "     Was Replaced by " + str(value) + "\n")
        for key, value in hostname_replacement_dictionary.items():
            output_dictionary.write("Origional Hostname " + str(key) + "     Was Replaced by " + str(value) + "\n")
        for key, value in domainname_replacement_dictionary.items():
            output_dictionary.write("Origional DomainName " + str(key) + "     Was Replaced by " + str(value) + "\n")
        for key, value in mac_replacement_dictionary.items():
            output_dictionary.write("Origional MAC Address " + str(key) + "     Was Replaced by " + str(value) + "\n")
        for key, value in username_replacement_dictionary.items():
            output_dictionary.write("Origional UserName " + str(key) + "     Was Replaced by " + str(value) + "\n")
        output_dictionary.close()

    except:
        print("something went bad opening/creating dictionary file for writing")
        print("Unexpected error:", sys.exc_info()[0])
        quit()
    return

if not args.nodictionary:
    create_output_dictionary()
#
#
# TidyUp and CleanUp
#
#
output_file.flush()
input_file.close()
output_file.close()
output_log.write(str(datetime.now()) + "     " + "Done Going Home Now " + "\n")
output_log.close()
print(str(datetime.now()) + "     " + "Done Going Home Now " + "\n")
quit()