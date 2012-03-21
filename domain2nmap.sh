#!/bin/bash
#
# Name: 	domain2nmap.sh
# Description: 	This script receive a web domain name and obtain a list 
#              	of associated domains and their IPs to make differents
#              	scans with nmap.
# Author: 	BrixtonC
# Date: 	15 Feb 2012
# Version:	0.4
# Example:	./domain2nmap.sh --help
#		./domain2nmap.sh www.cnn.com
#		./domain2nmap.sh -r shodan www.cnn.com
#		./domain2nmap.sh -s A -o normal www.sun.com
#

### FUNCTIONS

function Usage {
# This function show the sintax of script and some examples. This function
# is call by Arguments function or errors.
#

	echo -e " Sintax:\t$0 [OPTIONS] URL\n"
	echo -e " Options:\t* Search methods (-r)"
	echo -e " \t\t   all:  Search with all methods (default**)"
	echo -e " \t\t   bing: Bing search with IP operator"
	echo -e " \t\t   shodan: Shodan search with hostname operator"
	echo -e " \t\t   wget: Search with wget command"
	echo -e " \t\t* Scan types (-s)"
	echo -e " \t\t   A: ACK scan"
	echo -e " \t\t   P: Ping scan (default**)"
	echo -e " \t\t   S: SYN scan"
	echo -e " \t\t   U: UDP scan"
	echo -e " \t\t* Out types (-o)"
	echo -e " \t\t   grep: Save scan in grepable format"
	echo -e " \t\t   normal: Save scan in normal format"
	echo -e " \t\t   xml: Save scan in xml format (default**)\n"
	echo -e " \t\t** Without options the script it's call with default options\n"
	echo -e " Examples:\t$0 www.cnn.com\n\t\t$0 -s A -o normal www.sun.com"
	echo -e "\t\t$0 -r shodan www.microsoft.com\n\t\t$0 -r wget -s U www.cnn.com\n"
	exit 0

}

function Arguments() {
# This function check the number of arguments, print error if don't pass
# any argument and define the domain name objetive for Resolv function.
#

	if [ "$#" == "0" ]; then
	  echo -e "[*] ERROR: Valid domain name is required\n"
	  Usage
	else

	  if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	    Usage
	  else
	    local NAME="`echo $@ | awk '{print $NF;}' | sed 's/www\.//'`"
	    CheckDomain $NAME
	  fi

	fi

}

function CheckDomain() {
# This function run ping test to evaluate if the last argument's of script
# is a valid domain name and declarate the variable $DOMAIN. In wrong case,
# show error and exit.
#

	resolveip $1 > /dev/null

	[ "$?" != "0" ] && echo -e "[*] ERROR: '$1' not is a valid" \
	  "domain name" && exit 1 || DOMAIN="`echo $1`"

	echo -e "[+] Domain name: $DOMAIN"

}

function Options() {
# This function receive all arguments to obtain the scan and output options
# to run nmap command with respective options. In default case, without
# options, run the script with ping scan and xml output format.
#

	while getopts "r:s:o:" OPTION; do

	  case $OPTION in

	      r)
		if [ "$OPTARG" == "bing" ]; then
		  RESOLVTYPE="bing" && RESOLVNAME="Bing search"
		elif [ "$OPTARG" == "wget" ]; then
		  RESOLVTYPE="wget" && RESOLVNAME="Wget search"
		elif [ "$OPTARG" == "shodan" ]; then
		  RESOLVTYPE="shodan" && RESOLVNAME="Shodan search"
		elif [ "$OPTARG" == "all" ]; then
		  RESOLVTYPE="all" && RESOLVNAME="All methods"
		fi
		;;
	      s)
		if [ "$OPTARG" == "P" ]; then
		  SCANTYPE="-sn" && SCANNAME="Ping scan"
		elif [ "$OPTARG" == "S" ]; then
		  SCANTYPE="-sS" && SCANNAME="SYN scan"
		elif [ "$OPTARG" == "A" ]; then
		  SCANTYPE="-sA" && SCANNAME="ACK scan"
		elif [ "$OPTARG" == "U" ]; then
		  SCANTYPE="-sU" && SCANNAME="UDP scan"
		fi
		;;

	      o)
		if [ "$OPTARG" == "xml" ]; then
		  OUTTYPE="-oX" && OUTNAME="XML" && OUTEXT="xml"
		elif [ "$OPTARG" == "normal" ]; then
		  OUTTYPE="-oN" && OUTNAME="Normal" && OUTEXT="txt"
		elif [ "$OPTARG" == "grep" ]; then
		  OUTTYPE="-oG" && OUTNAME="Grep" && OUTEXT="log"
		fi
		;;

	  esac

	done

	[ -z "$SCANTYPE" ] && SCANTYPE="-sn" && SCANNAME="Ping scan (default)"
	[ -z "$OUTTYPE" ] && OUTTYPE="-oX" && OUTNAME="XML (default)" && \
	  OUTEXT="xml"
	[ -z "$RESOLVTYPE" ] && RESOLVTYPE="all" && RESOLVNAME="All methods (default)"
	
	echo -e "[+] Search type: $RESOLVNAME"
	echo -e "[+] Scan type: $SCANNAME"
	echo -e "[+] Output type: $OUTNAME"

}

function Resolv {
# This function decide watch kind of search use: Wget, Bing, Shodan or All.
#

	if [ "$RESOLVTYPE" == "wget" ]; then
	  WgetSearch
	elif [ "$RESOLVTYPE" == "bing" ]; then
	  BingSearch
	elif [ "$RESOLVTYPE" == "shodan" ]; then
	  ShodanSearch
	else
	  WgetSearch
	  BingSearch
	  ShodanSearch
	fi
	
	grep -v "[0-9]f*" tmp | sort | uniq > domains.lst
	rm -rf tmp

}

function WgetSearch {
# This function save index Web page of the domain and obtain a list
# of domains relationated with domain target.
#

	echo -e "[+] Wget search domain: $DOMAIN"

	wget -q $DOMAIN > /dev/null

	grep -oE "http://[a-z0-9\-\.]*\.$DOMAIN" index.html | \
	  cut -d "/" -f 3 >> tmp

	rm -rf index.html

}

function BingSearch {
# This function call Bing IP search to obtain a list of domains
# relationated with domain target.
#
# This functions is a modification of bing-ip2host script with
# GPLv3 license:
#
# http://www.morningstarsecurity.com/research/bing-ip2hosts
#

	local IP="`resolveip -s $DOMAIN`"
	local PAGE="0"

	echo -e "[+] Bing search IP: $IP"

	while (( "$PAGE" <= "10")); do

	    local URL="http://m.bing.com/search/search.aspx?A=webresults&Q=ip%3a$IP&D=Web&SI=$PAGE"

	    wget -q -O $IP-$PAGE.html $URL

	    grep -oE "[a-z0-9\-\.]*\.$DOMAIN" $IP-$PAGE.html >> tmp
	    rm -rf $IP-$PAGE.html

	    PAGE="$(($PAGE + 1))"

	done

}

function ShodanSearch {
# This function run a Shodan hostname search to obtain a list of domains
# relationated with domain target.
#

	local URL="http://www.shodanhq.com/search?q=hostname%3A$DOMAIN"

	echo -e "[+] Shodan search domain: $DOMAIN"

	wget -q -O index.html $URL > /dev/null

	grep -E "class='hostname'" index.html  | \
          grep -oE "http://[0-9a-z\.\-]*\.$DOMAIN" | \
            cut -d "/" -f 3 >> tmp

	rm -rf index.html

}

function ResolvDomain {
# This function receive obtained domains names of domain target
# and translate it to their IP address.
#

	echo -e "[+] Resolving domains"

	for NAMES in $(cat domains.lst); do

	  dig $DOMAIN | grep -oE "[0-9]{1,3}(\.[0-9]{1,3}){3}$" >> tmp

	done

	sort tmp | uniq > ipaddress.lst
	rm -rf tmp

}

function ScanIP {
# This function scan each host obtained with Resolv function throuth
# ipaddress.lst file and save the result in a file with IP and date
# as name.

	echo -e "[+] Scaning address"
	local NAME="${DOMAIN}_$(date +'%Y-%m-%d')"

	nmap $SCANTYPE $OUTTYPE $NAME.$OUTEXT -iL ipaddress.lst > /dev/null

	echo -e "[+] Filename: $NAME.$OUTEXT"

}

### SCRIPT

# Run Arguments function with all arguments separated to whitespaces to check
# the number of options and domain value.
#
Arguments $@

# Run Options function with all arguments to obtain the scan and output options
# to run the script
#
Options $@

# Run Resolv function with domain name as argument to obtain a list of
# related domains names.
#
Resolv

# Now check if exist domain.lst and ipaddress.lst file by use it in
# ResolvDomain and ScanIP functions. In wrong case show a error and run
# function Usage.
#
# FILE: domains.lst
[ ! -r domains.lst ] && echo "[*] ERROR: Can't read domains.lst file or" \
  "don't exist" && exit 2 || ResolvDomain
#
# FILE: ipaddress.lst
[ ! -r ipaddress.lst ] && echo -e "[*] ERROR: Can't read ipaddress.lst" \
  "file or don't exist" exit 3 || ScanIP

### NORMAL EXIT

# Show some exit messages.
#
echo -e "[+] Exit of script"

# Exit codes.
# 0 -> Succefull exit and function Usage()
# 1 -> No valid domain
# 2 -> Error file domains.lst
# 3 -> Error file ipaddress.lst
#
exit 0

#EOF
##FVE
