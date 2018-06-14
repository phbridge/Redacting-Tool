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
# 1.0 Implement IP masking
# 2.0 Implement hostname masking
# 3.0 Implement domain masking
# 4.0 Implement MAC address masking
# 5.0 Table masking
# 6.0 Implement Username/Password masking
#

import argparse  # needed for the nice menus and variable checking
from datetime import datetime  # needed for the datetime for filename
#import csv  # needed for parsing csv files in lazy way

parser = argparse.ArgumentParser(description='process input')
parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False,
                    help="Marking this flag accepts EULA embedded withing the script")
parser.add_argument("-v", "--verbose", action='store_true', default=False,
                    help="increase output verbosity", )
parser.add_argument("-IP", "--IP", action='store_true', default=False,
                    help="use this flag to modify all IP addresses")
parser.add_argument("-h", "--hostname", action='store_true', default=False,
                    help="use this flag to modify all hostnames")
parser.add_argument("-d", "--domain", action='store_true', default=False,
                    help="use this flag to modify all hostnames")
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

try:
    if args.verbose == True:
        print("trying to create file")
    output_filename = datetime.now()
    if args.verbose == True:
        print(str(output_filename))
    output_log = open(str(output_filename), 'a+')
    if args.verbose == True:
        print("file created sucessfully")
        output_log.write(str(datetime.now()) + "     " + "file created sucessfully " + "\n")
except:
    print("something went bad opening/creating file for writing")
    quit()























output_log.write(str(datetime.now()) + "     " + "Done Going Home Now " + "\n")
output_log.close()