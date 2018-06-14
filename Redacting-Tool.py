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
# 1.0 Implement Full IP masking (4 octet)
# 1.1 Implement Partial IP masking (first 3 octet)
# 1.2 Implement Partial IP masking (first 2 octet)
# 2.0 Implement hostname masking
# 3.0 Implement domain masking
# 4.0 Implement MAC address masking
# 5.0 Table masking
# 6.0 Implement Username/Password masking
# 7.0
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
parser.add_argument("-v", "--verbose", action='store_true', default=False,
                    help="increase output verbosity", )
parser.add_argument("-IP", "--IP", action='store_true', default=False,
                    help="use this flag to modify all IP addresses")
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
print("Arguments and files loaded")
if args.verbose == True:
    print(str(args.acceptedeula))
    print(str(args.verbose))
    print(str(args.IP))
    print(str(args.hostname))
    print(str(args.domain))
    print(str(args.mac))
    print(str(args.username))
    print(str(args.certificates))

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
if args.verbose:
    print("Arguments and files loaded")
    output_log.write(str(datetime.now()) + "     " + "-v Verbose flag set printing extended ouput" + "\n")

output_log.write(str(datetime.now()) + "     " + "Arguments and files loaded" + "\n")
output_log.write(str(datetime.now()) + "     " + "verbose flag is " + str(args.verbose) + "\n")
output_log.write(str(datetime.now()) + "     " + "IP flag is" + str(args.IP) + "\n")
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
    print("error opening input file")
    output_log.write(str(datetime.now()) + "     " + "error opening input file" + "\n")

#
#
# FIND ALL IP ADDRESSES
#
#
ip_address_list_raw = []
for line in input_file:
    working_line = []
    working_line = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
    for i in working_line:
        # print(working_line)
        # print(i)
        ip_address_list_raw.append(i)
    # print(line)

print(ip_address_list_raw)
ip_address_list = []

for i in ip_address_list_raw:
    if not i:
        # print("skipping empty array")
        continue
    if i not in ip_address_list:
        ip_address_list.append(i)

print(ip_address_list)
#
#
# NOW REPLACE IP ADDRESSES
#
#

#todo change this to accomodate full, 2 oct and 3 oct masking
random_address = '.'.join('%s'%random.randint(0, 255) for i in range(4))
print(random_address)
#
#
# NOW REPLACE HOSTNAMES
#
#

#               for i, j in dic.iteritems():
#                       text = text.replace(i, j)
#                   return text

#
#
# NOW REPLACE DOMAINS
#
#

#
#
# NOW REPLACE MAC ADDRESSES
#
#

#
#
# NOW REPLACE USERNAMES
#
#

#
#
# NOW REPLACE CERTIFICATES
#
#




input_file.close()

output_log.write(str(datetime.now()) + "     " + "Done Going Home Now " + "\n")
output_log.close()