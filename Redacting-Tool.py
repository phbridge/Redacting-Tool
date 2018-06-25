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
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges with a varity of Beer,
# Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and arrangements. Until provison of alcohol or
# baked goodies your on your own but there is no rocket sciecne involved so dont panic too much. To accept this EULA you must include
# the correct flag when running the script. If this script goes crazy wrong and breaks everything then your also on your own and Phil
# will not accept any liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held responsable
# for its use or if it goes bad, not can Cisco make any profit from this script. Phil can profit from this script but will not assuem
# any liability and all attempts to sue Phil will result in a non verbal response containing a single middle fingered response. Other
# than the boaring stuff please enjoy and plagerise as you like (as I have no ways to stop you) but common curtacy says to credit me
# in some way [see above comments on Beer, Wine, Steak and Greggs.].
#
# Version Control               Comments
# Version 0.01 Date 14/06/18     Inital draft
#
# Version 6.9 Date xx/xx/xx     Took over world and actuially got paid for value added work....If your reading this approach me on linkedin for details of weekend "daily" rate
# Version 7.0 Date xx/xx/xx     Note to the Gaffer - if your reading this then the above line is a joke only :-)
#
# ToDo *******************TO DO*********************
# 1.0 Implement Full IP masking (4 octet)                   DONE
# 1.1 Implement Partial IP masking (first 3 octet)          DONE
# 1.2 Implement Partial IP masking (first 2 octet)          DONE
# 1.3 Implement IPv6 masking                                DONE
# 2.0 Implement hostname masking
# 3.0 Implement domain masking
# 4.0 Implement MAC address masking
# 5.0 Table masking                                         DONE
# 6.0 Implement Username/Password masking
# 7.0 Implement Wget Counter
# 8.0 Implement wipeout masking                             DONE
#

import argparse                 # needed for the nice menus and variable checking
from datetime import datetime   # needed for the datetime for filename
import re                       # Regular expression usage for finding things
import random                   # used for random IP address generation

parser = argparse.ArgumentParser(description='process input')
parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False, required="True",
                    help="Marking this flag accepts EULA embedded withing the script")
parser.add_argument("-i", "--inputfile", required=True, type=argparse.FileType('r', encoding='UTF-8'),
                    help="input file that needs to be redacted")
parser.add_argument("-o", "--outputfile", required=False, type=argparse.FileType('r', encoding='UTF-8'),
                    help="input file that needs to be redacted")
parser.add_argument("-v", "--verbose", action='store_true', default=False,
                    help="increase output verbosity", )
parser.add_argument("-IP1", "--IPv4_1", action='store_true', default=False,
                    help="use this flag to modify all IP addresses 1st octet only")
parser.add_argument("-IP2", "--IPv4_2", action='store_true', default=False,
                    help="use this flag to modify all IP addresses 1st + 2nd octet only")
parser.add_argument("-IP3", "--IPv4_3", action='store_true', default=False,
                    help="use this flag to modify all IP addresses 1st + 2nd + 3rd octet only")
parser.add_argument("-IP4", "--IPv4_4", action='store_true', default=False,
                    help="use this flag to modify all IP addresses whole IP address")
parser.add_argument("-1v6", "--IPv6_1", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st colon")
parser.add_argument("-2v6", "--IPv6_2", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st + 2nd colon")
parser.add_argument("-3v6", "--IPv6_3", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st, 2nd + 3rd colon")
parser.add_argument("-4v6", "--IPv6_4", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st, 2nd, 3rd + 4th colon")
parser.add_argument("-5v6", "--IPv6_5", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st, 2nd, 3rd, 4th + 5th colon")
parser.add_argument("-6v6", "--IPv6_6", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st, 2nd, 3rd, 4th, 5th + 6th colon")
parser.add_argument("-7v6", "--IPv6_7", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st, 2nd, 3rd, 4th, 5th, 6th + 7th colon")
parser.add_argument("-8v6", "--IPv6_8", action='store_true', default=False,
                    help="use this flag to modify all IPv6 addresses 1st, 2nd, 3rd, 4th, 5th, 6th, 7th + 8th colon")
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
                    help="use this flag to modify all certificates")

args = parser.parse_args()

if args.acceptedeula == False:
    print("""you need to accept the EULA agreement which is as follows:-
# EULA
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges with a varity of Beer, 
# Wine, Steak and Greggs pasties. Please contact phbridge@cisoc.com for support costs and arrangements. Until provison of alcohol or 
# baked goodies your on your own but there is no rocket sciecne involved so dont panic too much. To accept this EULA you must include 
# the correct flag when running the script. If this script goes crazy wrong and breaks everything then your also on your own and Phil 
# will not accept any liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held responsable 
# for its use or if it goes bad, not can Cisco make any profit from this script. Phil can profit from this script but will not assuem 
# any liability and all attempts to sue Phil will result in a non verbal response containing a single middle fingered response. Other 
# than the boaring stuff please enjoy and plagerise as you like (as I have no ways to stop you) but common curtacy says to credit me 
# in some way [see above comments on Beer, Wine, Steak and Greggs..

# To accept the EULA please run with the -ACCEPTEULA flag
    """)
    quit()

if args.verbose == True:
    print("-v Verbose flag set printing extended ouput")
    print("seed file loaded is ", str(args.seedfile.name))
print(str(datetime.now()) + "     " +"Arguments and files loaded")
if args.verbose == True:
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
    print(str(args.output_filename))

#
#
# NOW LOGFILE STUFF
#
#

#format_date = datetime.strptime(args.date, "%Y-%m-%d")

try:
    output_filename = str(datetime.now()) + "-Redacting-Tool"
    output_log = open(str(output_filename) + ".text", 'a+')
    output_log.write(str(datetime.now()) + "     " + "log file created sucessfully file name should be " +
                     str(output_filename) + "\n")
except:
    print("something went bad opening/creating file for writing")
    print("Unexpected error:", sys.exc_info()[0])
    quit()

# Open output file


try:
    if args.outputfile is None:
        output_file_name = str(str(datetime.now()) + "-OutputFile")
        print(str(datetime.now()) + "     " + "output file created with name " + str(output_file_name))
    else:
        output_file_name = str(args.outputfile.name)
        print(str(datetime.now()) + "     " + "output file created with name " + str(output_file_name))
    output_file = open(str(output_file_name) + ".text", 'a+')

    print(str(datetime.now()) + "     " + "output file created and opened")

except:
    print("something went bad opening/creating output file for writing")
    print("Unexpected error:", sys.exc_info()[0])
    quit()

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

#
#
# NOW LOAD THE INPUT FILE
#
#
try:
    input_file = open(args.inputfile.name)
    output_log.write(str(datetime.now()) + "     " + "input file opened" + "\n")
except:
    print(str(datetime.now()) + "     " + "error opening input file")
    output_log.write(str(datetime.now()) + "     " + "error opening input file" + "\n")
#
#
# FIND ALL IP ADDRESSES
#
#

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
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv4 IN THIS PASS ###########" + "\n")

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
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
    output_log.write(
        str(datetime.now()) + "     " + "########### WARNING WE ARE NOT MASKING IPv6 IN THIS PASS ###########" + "\n")
#
# Find All IPv4 addresses
#
ipv4_address_list_raw = []
for line in input_file:
    working_line = []
    working_line = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
    for i in working_line:
        ipv4_address_list_raw.append(i)

output_log.write(str(datetime.now()) + "     " + "here is the RAW address list" + str(ipv4_address_list_raw) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the RAW address list length is " + str(len(ipv4_address_list_raw)) + "\n")
print(str(datetime.now()) + "     " + str(len(ipv4_address_list_raw)) + " IP addresses found")
#
# Find All IPv6 addresses
#
input_file.seek(0)
ipv6_address_list_raw = []
ipv6_regex = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'                              
                        '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
                        '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
                        '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
                        '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                        '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
                        '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
                        '([0-9a-fA-F]{1,4}:){1,7}:)')
for line in input_file:
    ipv6_working_line = []
    ipv6_working_line = ipv6_regex.findall(line)
    if not ipv6_working_line == []:
        for i in ipv6_working_line:
            ipv6_address_list_raw.append(i[0])

output_log.write(str(datetime.now()) + "     " + "here is the RAW address list" + str(ipv6_address_list_raw) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the RAW address list length is " + str(len(ipv6_address_list_raw)) + "\n")
print(str(datetime.now()) + "     " + str(len(ipv6_address_list_raw)) + " IPv6 addresses found")

#
# Unique IPv4 address list
#

ipv4_address_list = []
for i in ipv4_address_list_raw:
    if not i:
        continue
    if i not in ipv4_address_list:
        ipv4_address_list.append(i)

output_log.write(str(datetime.now()) + "     " + "here is the no dup list is " + str(ipv4_address_list) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the Rno dup list length is " + str(len(ipv4_address_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(ipv4_address_list)) + " unique IP addresses found")

#
# Unique IPv6 address list
#

ipv6_address_list = []
for i in ipv6_address_list_raw:
    if not i:
        continue
    if i not in ipv6_address_list:
        ipv6_address_list.append(i)

output_log.write(str(datetime.now()) + "     " + "here is the no dup ipv6 list is " + str(ipv6_address_list) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the Rno dup ipv6 list length is " + str(len(ipv6_address_list)) + "\n")
print(str(datetime.now()) + "     " + str(len(ipv6_address_list)) + " unique IPv6 addresses found")
#
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
#
# NOW REPLACE IP ADDRESSES
#
#

#
# IPv4 replacement
#
ipv4substrs = sorted(ipv4_replacement_dictionary, key=len, reverse=True)
ipv6substrs = sorted(ipv6_replacement_dictionary, key=len, reverse=True)
ipv4regexp = re.compile('|'.join(map(re.escape, ipv4substrs)))
ipv6regexp = re.compile('|'.join(map(re.escape, ipv6substrs)))
input_file.seek(0)
lines_done = 0
start_time = datetime.now()

for line in input_file:
    first_pass = str(ipv4regexp.sub(lambda match: ipv4_replacement_dictionary[match.group(0)], line))
    output_file.write(str(ipv6regexp.sub(lambda match: ipv6_replacement_dictionary[match.group(0)], first_pass)))
    lines_done += 1

end_time = datetime.now()

if not ipv4_octets_to_replace == 0:
    print(str(datetime.now()) + "     " + "done replaced " + str(len(ipv4_address_list_raw)) + " IPv4 adddress hidden in " +
          str(lines_done) + " lines in " + str(end_time-start_time) + " seconds")
else:
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
if not ipv6_octets_to_replace == 0:
    print(str(datetime.now()) + "     " + "done replaced " + str(len(ipv6_address_list_raw)) + " IPv6 adddress hidden in " +
          str(lines_done) + " lines in " + str(end_time-start_time) + " seconds")
else:
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")
    print(str(datetime.now()) + "     " + "done BUT REPLACED NO IPv4")

output_log.write(str(datetime.now()) + "     " + "replaced  " + str(len(ipv4_address_list_raw)) +" IPv4 addresses" + "\n")
output_log.write(str(datetime.now()) + "     " + "replaced  " + str(len(ipv6_address_list_raw)) + " IPv6 addresses" + "\n")
output_log.write(str(datetime.now()) + "     " + "hidden in   " + str(lines_done) + " lines of output" + "\n")
output_log.write(str(datetime.now()) + "     " + "in " + str(end_time-start_time) + " seconds" + "\n")

#
# If dictionary was used export dictionary to file now
#

if not args.nodictionary:
    try:
        output_dictionary_filename = str(datetime.now()) + "-Dictionary-Redacting-Tool"
        output_dictionary = open(str(output_dictionary_filename) + ".text", 'a+')
        for key, value in ipv4_replacement_dictionary.items():
            output_dictionary.write("Origional Address " + str(key) + "     Was Replaced by " + str(value) + "\n")
        for key, value in ipv6_replacement_dictionary.items():
            output_dictionary.write("Origional Address " + str(key) + "     Was Replaced by " + str(value) + "\n")
        output_dictionary.close()

    except:
        print("something went bad opening/creating dictionary file for writing")
        print("Unexpected error:", sys.exc_info()[0])
        quit()
#
#
# NOW REPLACE HOSTNAMES
#
#

#
# Find All HostNames
#
input_file.seek(0)
hostname_list_raw = []
hostname_regex = re.compile(r'^hostname\s*(.*)')
for line in input_file:
    hostname_working_line = []
    hostname_working_line = hostname_regex.findall(line)
    if not hostname_working_line == []:
        for i in hostname_working_line:
            hostname_list_raw.append(i)

output_log.write(str(datetime.now()) + "     " + "here is the RAW hostname list" + str(hostname_list_raw) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the RAW hostname list length is " + str(len(hostname_list_raw)) + "\n")
print(str(datetime.now()) + "     " + str(len(hostname_list_raw)) + " hostname found")
print(str(hostname_list_raw[0]))
#
#
# NOW REPLACE DOMAINS
#
#
input_file.seek(0)
domain_list_raw = []
domain_regex = re.compile(r'^ip domain name\s*(.*)')
for line in input_file:
    domain_working_line = []
    domain_working_line = domain_regex.findall(line)
    if not domain_working_line == []:
        for i in domain_working_line:
            domain_list_raw.append(i)

output_log.write(str(datetime.now()) + "     " + "here is the RAW domain list" + str(domain_list_raw) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the RAW domain list length is " + str(len(domain_list_raw)) + "\n")
print(str(datetime.now()) + "     " + str(len(hostname_list_raw)) + " domains found")
print(str(domain_list_raw[0]))

#
#
# NOW REPLACE MAC ADDRESSES
#
#

input_file.seek(0)
mac_address_list_raw = []
mac_regex = re.compile('(([0-9a-fA-F]{4}[\.]){2}[0-9a-fA-F]{4})')
for line in input_file:
    mac_working_line = []
    mac_working_line = mac_regex.findall(line)
    if not mac_working_line == []:
        for i in mac_working_line:
            mac_address_list_raw.append(i[0])

print(str(mac_address_list_raw))
output_log.write(str(datetime.now()) + "     " + "here is the RAW mac address list" + str(mac_address_list_raw) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the RAW mac address list length is " + str(len(mac_address_list_raw)) + "\n")
print(str(datetime.now()) + "     " + str(len(mac_address_list_raw)) + " MAC addresses found")

#
#
# NOW REPLACE USERNAMES
#
#
input_file.seek(0)
username_list_raw = []
username_regex = re.compile(r'^username \s*(.*)')
for line in input_file:
    username_working_line = []
    username_working_line = domain_regex.findall(line)
    if not username_working_line == []:
        for i in username_working_line:
            username_list_raw.append(i)

output_log.write(str(datetime.now()) + "     " + "here is the RAW domain list" + str(username_list_raw) + "\n")
output_log.write(str(datetime.now()) + "     " + "here is the RAW domain list length is " + str(len(username_list_raw)) + "\n")
print(str(datetime.now()) + "     " + str(len(username_list_raw)) + " domains found")

mac_address_list = []
for i in mac_address_list_raw:
    if not i:
        continue
    if i not in mac_address_list:
        mac_address_list.append(i)

print(str(mac_address_list))
#
#
# NOW REPLACE CERTIFICATES
#
#

#
#
# TidyUp and CleanUp
#
#

input_file.close()
output_file.close()
output_log.write(str(datetime.now()) + "     " + "Done Going Home Now " + "\n")
output_log.close()
print(str(datetime.now()) + "     " + "Done Going Home Now " + "\n")
quit()