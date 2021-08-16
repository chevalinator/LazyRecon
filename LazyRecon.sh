#!/bin/bash

VERSION="1.3"

TARGET=$1

WORKING_DIR=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
TOOLS_PATH="$WORKING_DIR/tools"
WORDLIST_PATH="$WORKING_DIR/wordlists"
RESULTS_PATH="$WORKING_DIR/results/$TARGET"
SUB_PATH="$RESULTS_PATH/subdomain"
CORS_PATH="$RESULTS_PATH/cors"
IP_PATH="$RESULTS_PATH/ip"
PSCAN_PATH="$RESULTS_PATH/portscan"
SSHOT_PATH="$RESULTS_PATH/screenshot"
DIR_PATH="$RESULTS_PATH/directory"
VULN_PATH="$RESULTS_PATH/vulnerability"

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

displayLogo(){
echo -e "
██╗      █████╗ ███████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║     ██╔══██╗╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║     ███████║  ███╔╝  ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║     ██╔══██║ ███╔╝    ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████╗██║  ██║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══  
${RED}v$VERSION${RESET} by ${YELLOW}@CaptMeelo${RESET}
"
}

checkArgs(){
    if [[ $# -eq 0 ]]; then
	echo -e "$#"
        echo -e "${RED}[+] Usage:${RESET} $0 <domain>\n"
        exit 1
    fi
}


runBanner(){
    name=$1
    echo -e "${RED}\n[+] Running $name...${RESET}"
}


setupDir(){
    echo -e "${GREEN}--==[ Setting things up ]==--${RESET}"
    echo -e "${RED}\n[+] Creating results directories...${RESET}"
    #rm -rf $RESULTS_PATH
    mkdir -p $SUB_PATH $CORS_PATH $IP_PATH $PSCAN_PATH $SSHOT_PATH $DIR_PATH $VULN_PATH
    echo -e "${BLUE}[*] $SUB_PATH${RESET}"
    echo -e "${BLUE}[*] $CORS_PATH${RESET}"
    echo -e "${BLUE}[*] $IP_PATH${RESET}"
    echo -e "${BLUE}[*] $PSCAN_PATH${RESET}"
    echo -e "${BLUE}[*] $SSHOT_PATH${RESET}"
    echo -e "${BLUE}[*] $DIR_PATH${RESET}"
    echo -e "${BLUE}[*] $VULN_PATH${RESET}"
}

enumSubsTopDomains(){
    echo -e "${GREEN}\n--==[ Enumerating subdomains of top domains passed in argument  ]==--${RESET}"

    TOPDOMAINLIST=$TARGET
    if [[ $# -eq 1 ]]; then
	echo -e "loading domains from $TOPDOMAINLIST and enumerating them"
        FILEPATH=$1
    fi
    for domain in $(cat $TOPDOMAINLIST); do
	echo -e "Enumerating $domain"
    	runBanner "Amass"
	~/go/bin/amass enum -d $domain -o $SUB_PATH/amass$domain.txt

	runBanner "subfinder"
	~/go/bin/subfinder -d $domain -t 50 -dL $WORDLIST_PATH/dns_all.txt -nW -silent -o $SUB_PATH/subfinder$domain.txt

	runBanner "sublist3r"
	python $TOOLS_PATH/Sublist3r/sublist3r.py -d $domain -o $SUB_PATH/sublist3r$domain.txt
    done
    combineSubdomains
}


enumSubs(){
    echo -e "${GREEN}\n--==[ Enumerating subdomains ]==--${RESET}"
    runBanner "Amass"
    ~/go/bin/amass enum -d $TARGET -o $SUB_PATH/amass.txt

    runBanner "subfinder"
    ~/go/bin/subfinder -d $TARGET -t 50 -dL $WORDLIST_PATH/dns_all.txt -nW -silent -o $SUB_PATH/subfinder.txt

    runBanner "sublist3r"
    python $TOOLS_PATH/Sublist3r/sublist3r.py -d $TARGET -o $SUB_PATH/sublist3r.txt

    combineSubdomains
    checkSubdomainsTakeover

}

combineSubdomains(){
    echo -e "${RED}\n[+] Combining subdomains...${RESET}"
    cat $SUB_PATH/*.txt | sort | awk '{print tolower($0)}' | uniq > $SUB_PATH/final-subdomains.txt
    echo -e "${BLUE}[*] Check the list of subdomains at $SUB_PATH/final-subdomains.txt${RESET}"
}

checkSubdomainsTakeover(){
    echo -e "${GREEN}\n--==[ Checking for subdomain takeovers ]==--${RESET}"
    runBanner "subjack"
    ~/go/bin/subjack -a -ssl -t 50 -v -c ~/go/src/github.com/haccer/subjack/fingerprints.json -w $SUB_PATH/final-subdomains.txt -o $SUB_PATH/final-takeover.tmp
    cat $SUB_PATH/final-takeover.tmp | grep -v "Not Vulnerable" > $SUB_PATH/final-takeover.txt
    rm $SUB_PATH/final-takeover.tmp
    echo -e "${BLUE}[*] Check subjack's result at $SUB_PATH/final-takeover.txt${RESET}"
}


corsScan(){
    echo -e "${GREEN}\n--==[ Checking CORS configuration ]==--${RESET}"
    runBanner "CORScanner"
    python $TOOLS_PATH/CORScanner/cors_scan.py -v -t 50 -i $SUB_PATH/httprobe_urls.txt2 | tee $CORS_PATH/final-cors.txt
    echo -e "${BLUE}[*] Check the result at $CORS_PATH/final-cors.txt${RESET}"
}


enumIPs(){
    echo -e "${GREEN}\n--==[ Resolving IP addresses ]==--${RESET}"
    runBanner "massdns"
    $TOOLS_PATH/massdns/bin/massdns -r $TOOLS_PATH/massdns/lists/resolvers.txt -q -t A -o S -w $IP_PATH/massdns.raw $SUB_PATH/final-subdomains.txt
    cat $IP_PATH/massdns.raw | grep -e ' A ' |  cut -d 'A' -f 2 | tr -d ' ' > $IP_PATH/massdns.txt
    cat $IP_PATH/*.txt | sort -V | uniq > $IP_PATH/final-ips.txt
    echo -e "${BLUE}[*] Check the list of IP addresses at $IP_PATH/final-ips.txt${RESET}"
}


portScan(){
    echo -e "${GREEN}\n--==[ Port-scanning targets ]==--${RESET}"
    runBanner "masscan"
    sudo $TOOLS_PATH/masscan/bin/masscan -p 1-65535 --rate 5000 --wait 0 --open -iL $IP_PATH/final-ips.txt -oX $PSCAN_PATH/masscan.xml
    xsltproc -o $PSCAN_PATH/final-masscan.html $TOOLS_PATH/nmap-bootstrap.xsl $PSCAN_PATH/masscan.xml
    open_ports=$(cat $PSCAN_PATH/masscan.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
    echo -e "${BLUE}[*] Masscan Done! View the HTML report at $PSCAN_PATH/final-masscan.html${RESET}"

    runBanner "nmap"
    sudo nmap -sVC -p $open_ports --open -v -T4 -Pn -iL $SUB_PATH/final-subdomains.txt -oX $PSCAN_PATH/nmap.xml
    xsltproc -o $PSCAN_PATH/final-nmap.html $PSCAN_PATH/nmap.xml
    echo -e "${BLUE}[*] Nmap Done! View the HTML report at $PSCAN_PATH/final-nmap.html${RESET}"
}

runNmapOnly(){
    runBanner "nmap"
    sudo nmap -sVC --top-ports 1000 --open -v -T4 -Pn -iL $SUB_PATH/final-subdomains.txt -oX $PSCAN_PATH/nmap.xml
    xsltproc -o $PSCAN_PATH/final-nmap.html $PSCAN_PATH/nmap.xml
    echo -e "${BLUE}[*] Nmap Done! View the HTML report at $PSCAN_PATH/final-nmap.html${RESET}"
}


checkHttpUsingProbe(){
    echo -e "${GREEN}\n--==[ Running httpprobe ]==--${RESET}"
    runBanner "httpprobe"
    cat $SUB_PATH/final-subdomains.txt | ~/go/bin/httprobe -t 10000 > $SUB_PATH/httprobe_urls.txt2
    echo -e "${BLUE}[*] Check the result at $SUB_PATH/httprobe_urls.txt2${RESET}"
}

visualRecon(){
    echo -e "${GREEN}\n--==[ Taking screenshots ]==--${RESET}"
    runBanner "aquatone"
    cat $SUB_PATH/final-subdomains.txt | ~/go/bin/aquatone -http-timeout 10000 -scan-timeout 300 -ports xlarge -out $SSHOT_PATH/aquatone/
    echo -e "${BLUE}[*] Check the result at $SSHOT_PATH/aquatone/aquatone_report.html${RESET}"
}


checkbackupfiles(){
    echo -e "${GREEN}\n--==[ Checking for backupfiles ]==--${RESET}"
    runBanner "ohmybackup"
    pushd /usr/share/wordlists/ohmybackdup
    urlWithoutTrailingSlash=$(echo $1 | sed 's:/*$::')
    ~/go/bin/ohmybackup --hostname $urlWithoutTrailingSlash  | tee $DIR_PATH/dirsearch/$2_backdup.txt
    popd

}

bruteDir(){
    echo -e "${GREEN}\n--==[ Bruteforcing directories ]==--${RESET}"
    runBanner "dirsearch"
    echo -e "${BLUE}[*]Creating output directory...${RESET}"
    mkdir -p $DIR_PATH/dirsearch

    FILEPATH=$SSHOT_PATH/aquatone/aquatone_urls.txt
    if [[ $# -eq 1 ]]; then
	echo -e "loading domains from $1 and bruteforcing them"
        FILEPATH=$1
    fi
    for url in $(cat $FILEPATH); do
        fqdn=$(echo $url | sed -e 's;https\?://;;' | sed -e 's;/.*$;;')
        #$TOOLS_PATH/dirsearch/dirsearch.py -b -t 100 -e php,asp,aspx,jsp,html,zip,jar,sql -x 500,503 -r -w $WORDLIST_PATH/raft-large-words.txt -u $url --plain-text-report=$DIR_PATH/dirsearch/$fqdn.tmp
        $TOOLS_PATH/dirsearch/dirsearch.py -b -t 100 -e php,asp,aspx,jsp,html,zip,jar,sql -x 500,503 -r -w $WORDLIST_PATH/raft-large-words.txt -u $url --output=$DIR_PATH/dirsearch/$fqdn.html --format=html

	checkbackupfiles $url $fqdn
	#used to sort results but not used anymore since we output in html
        #if [ ! -s $DIR_PATH/dirsearch/$fqdn.tmp ]; then
        #    rm $DIR_PATH/dirsearch/$fqdn.tmp
        #else
        #    cat $DIR_PATH/dirsearch/$fqdn.tmp | sort -k 1 -n > $DIR_PATH/dirsearch/$fqdn.txt
        #    rm $DIR_PATH/dirsearch/$fqdn.tmp
	#    checkbackupfiles $url $fqdn
        #fi
    done
    echo -e "${BLUE}[*] Check the results at $DIR_PATH/dirsearch/${RESET}"
}

bruteDirOnly(){
    echo -e "${GREEN}\n--==[ Bruteforcing directories ]==--${RESET}"
    runBanner "dirsearch"
    echo -e "${BLUE}[*]Creating output directory...${RESET}"
    mkdir -p $DIR_PATH/dirsearch

    url="https://$TARGET"
    fqdn=$(echo $url | sed -e 's;https\?://;;' | sed -e 's;/.*$;;')

    #$TOOLS_PATH/dirsearch/dirsearch.py -b -t 50 -e php,asp,aspx,jsp,html,zip,jar,sql -x 500,503 -r -w $WORDLIST_PATH/raft-large-words.txt -u $url --plain-text-report=$DIR_PATH/dirsearch/$fqdn.tmp --timeout=10
    $TOOLS_PATH/dirsearch/dirsearch.py -b -t 50 -e php,asp,aspx,jsp,html,zip,jar,sql -x 500,503 -r -w $WORDLIST_PATH/raft-large-words.txt -u $url --output=$DIR_PATH/dirsearch/$fqdn.html --format=html --timeout=10

    checkbackupfiles $url $fqdn
    #used to sort results but not used anymore since we output in html
    #if [ ! -s $DIR_PATH/dirsearch/$fqdn.tmp ]; then
    #  rm $DIR_PATH/dirsearch/$fqdn.tmp
    #else
    #  cat $DIR_PATH/dirsearch/$fqdn.tmp | sort -k 1 -n > $DIR_PATH/dirsearch/$fqdn.html
    #  rm $DIR_PATH/dirsearch/$fqdn.tmp
    #fi

}

checkTekerikRCE(){
    echo -e "${GREEN}\n--==[Test for Telerik UI ASP.NET AJAX RCE ]==--${RESET}"

    #Allow to test the target directly if HTTP Probe file doesn't exist
    if [ "$(curl --max-time 10 -sk $TARGET/Telerik.Web.UI.WebResource.axd?type=rau | grep "{ \"message\" : \"RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly.\" }")" != "" ]; then
        echo -e "${RED}[!] $TARGET might be vulnerable to CVE-2019-18935 RCE exploitation \n${RESET}"
	echo "$TARGET might be vulnerable to CVE-2019-18935 RCE exploitation" >> $VULN_PATH/telerikCVE-2019-18935.txt
    else
        echo -e "${BLUE}$TARGET Not vulnerable \n${RESET}"
    fi

    FILEPATH=$SUB_PATH/httprobe_urls.txt2
    for url in $(cat $FILEPATH); do
        if [ "$(curl -sk $url/Telerik.Web.UI.WebResource.axd?type=rau | grep "{ \"message\" : \"RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly.\" }")" != "" ]; then
      	  echo -e "${RED}[!] $url might be vulnerable to CVE-2019-18935 RCE exploitation \n${RESET}"
	  echo "$url might be vulnerable to CVE-2019-18935 RCE exploitation" >> $VULN_PATH/telerikCVE-2019-18935.txt
    	else
          echo -e "${BLUE}$url Not vulnerable \n${RESET}"
        fi
    done


}

# Main function
displayLogo
checkArgs $TARGET

#parse arguments

	POSITIONAL=()
	while [[ $# -gt 0 ]]
	do
	key="$1"
	case $key in
	    -hp|--httpprobe)
            echo "running httpprobe"
	    checkHttpUsingProbe
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -as|--addsubdomains)
            echo "Combining all subdomains files in subdomain folder and putting result in final-subdomains.txt"
	    combineSubdomains
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -bl|--brutelistdomains)
            echo "Bruteforce the list of domains provided in the file passed in the command line"
	    bruteDir $TARGET
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -bo|--bruteforceonly)
            echo "Bruteforce the specified domain only without doing anything else"
	    bruteDirOnly
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -cs|--checksubdomains)
            echo "Check subdomains takeofer using resutls in final-subdomains.txt"
	    checkSubdomainsTakeover
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -ep|--enumprobe)
	    echo "Enumerate subdomains then HttpProbe"
	    setupDir
	    enumSubs
	    checkHttpUsingProbe
	    corsScan
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -etcs|--enumtopchecksub)
	    echo "Enumerate subdomains of the file containing top domains passed in argument then check for subdomains takeover"
	    setupDir
	    enumSubsTopDomains	
	    checkSubdomainsTakeover
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -nm|--nmap)
	    echo "Run nmap on subdomains in final-subdomains.txt "
	    runNmapOnly	    
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -ps|--portscan)
	    echo "Enumerate the ips from the subdomains then Portscan"
	    enumIPs
	    portScan
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -ss|--skipsubdomains)
            echo "Do the whole process skipping domain enumeration, using subdomains listed in final-subdomains.txt directly"
	    combineSubdomains
	    checkSubdomainsTakeover
	    checkHttpUsingProbe
	    checkTekerikRCE
	    corsScan
	    enumIPs
	    portScan
	    visualRecon
	    bruteDir
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -tt|--testtelerik)
            echo "Test for Telerik ASP.NET AJAX presence. This can lead to RCE via CVE-2019-18935"
	    checkTekerikRCE
            exit 1
	    shift # past argument
	    shift # past value
	    ;;
	    -l|--lib)
	    LIBPATH="$2"
	    shift # past argument
	    shift # past value
	    ;;
	    -h|--help)
	    echo "-as, --addsubdomains     Combining all subdomains files in subdomain folder and putting result in final-subdomains.txt"
	    echo "-bl, --brutelistdomains  Bruteforce the list of domains provided in the file passed in the command line"
	    echo "-bo, --bruteforceonly    Bruteforce the specified domain only without doing anything else"
	    echo "-cs, --checksubdomains   Check subdomains takeover using resutls in final-subdomains.txt"
	    echo "-ep, --enumprobe         Enumerate subdomains then HttpProbe"
	    echo "-etcs, --enumtopchecksub Enumerate subdomains of the file containing top domains passed in argument then check for subdomains takeover"
	    echo "-hp, --httpprobe         Run HttpProbe with subdomains stored in final-subdomains.txt"
	    echo "-nm, --nmap		   Run nmap on subdomains in final-subdomains.txt"
	    echo "-ps, --portscan          Enumerate the ips from the subdomains then Portscan"
	    echo "-ss  --skipsubdomains    Do the whole process skipping domain enumeration, using subdomains listed in final-subdomains.txt directly"
	    echo "-tt  --testtelerik       Test for Telerik ASP.NET AJAX presence. This can lead to RCE via CVE-2019-18935"
            exit 1
	    shift # past argument
	    ;;
	    *)    # unknown option
	    POSITIONAL+=("$1") # save it in an array for later
	    shift # past argument
	    ;;
	esac
	done
	set -- "${POSITIONAL[@]}" # restore positional parameters

	echo "FILE EXTENSION  = ${EXTENSION}"
	echo "SEARCH PATH     = ${SEARCHPATH}"
	echo "LIBRARY PATH    = ${LIBPATH}"
	echo "DEFAULT         = ${DEFAULT}"


#Main function
setupDir
enumSubs
checkHttpUsingProbe
checkTekerikRCE
corsScan
enumIPs
portScan
visualRecon
bruteDir

echo -e "${GREEN}\n--==[ DONE ]==--${RESET}"
