#!/bin/bash
# Author : andypitcher
# CVE-2021-44228 vulnerability in Apache Log4j library
# This script looks for vulnerable log4j librairies and log4shell rce attempts
# Usage: ./log4j-checker.sh
# Features:
# Vulnerability/Versions -> retrieve log4j libraries and vulnerability JndiLookup.class
# Detection -> Search for RCE attempts in /var/log and Search for .sh/.class files added since December 1 2021
# Output : log4j_full_report.txt

log4j_libs=/tmp/log4j_libs.txt
log4j_processes=/tmp/log4j_processes.txt
log4j_logs=/tmp/log4j_logs.txt
log4j_logs_attack=/tmp/log4j_logs_attack.txt
log4j_vulnerable_libs=/tmp/log4j_vulnerable_libs.txt
log4j_full_report=/tmp/log4j_full_report.txt

log4j_print_version () {
    cat $log4j_libs |  grep -Eo '[0-9.]{6}' | uniq
}

log4j_find_processes () {

echo "\n[Collect] Searching for log4j processes..."      | tee -a $log4j_full_report
ps aux | grep -i log4 | grep -v 'log4j-check\|grep\|tee' | tee -a $log4j_processes $log4j_full_report

}

log4j_find_logs () {

echo "\n[Collect] Searching for logs..." | tee -a $log4j_full_report
find /var/log -type f                    | tee -a $log4j_logs $log4j_full_report

}

log4j_find_libs () {

echo "\n[Collect] Searching for log4j packages..." | tee -a $log4j_full_report
find / -name "log4j*" 2>/dev/null | grep 'jar$'    | tee -a $log4j_libs $log4j_full_report

}

log4j_find_jndilookup_libs () {

echo "\n[Vulnerability] Searching for log4j JndiLookup.class...\n" | tee -a $log4j_full_report
for libs in $(cat $log4j_libs)
do
        if zipinfo $libs | grep -q JndiLookup.class 2>/dev/null
        then
                echo "$libs"                                    | tee -a $log4j_vulnerable_libs $log4j_full_report

        fi
done
}

log4j_rce_detection(){

echo "\n[Detection] Searching for log4j exploit attempts...\n" | tee -a $log4j_full_report
for logs in $(cat $log4j_logs)
do
        zgrep -E -i '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+' $logs 2>/dev/null | tee -a $log4j_logs_attack  $log4j_full_report

done

}

log4j_attacker_traces(){

echo "\n[Detection] Gathering attacker's traces..."     | tee -a $log4j_full_report

for attacker in $(cat $log4j_logs_attack | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | uniq)
do
        echo "\n**$attacker** - traces found:"          | tee -a $log4j_full_report
        for logs in $(cat $log4j_logs)
        do
                zgrep -i $attacker $logs 2>/dev/null   | tee -a $log4j_full_report
        done
        break
done

}

log4j_postexploit_detection (){

echo "\n[Detection] Searching for log4j post exploit files..."                 | tee -a $log4j_full_report
touch --date "2021-12-01" log4j_exploit.date
find / -type f -newer log4j_exploit.date \( -name "*.class" -o -name "*.sh" \) | tee -a $log4j_full_report
rm log4j_exploit.date

}

log4j_check () {

echo "LOG4J-CHECKER for Apache Log4J Dec 2021 : CVE-2021-44228\nHostname: $(hostname)\nDate: $(date +%m-%d-%Y)" | tee -a $log4j_full_report
# Execution and checks
log4j_find_libs
log4j_find_logs
log4j_find_processes
log4j_find_jndilookup_libs
log4j_rce_detection
log4j_attacker_traces
log4j_postexploit_detection

if [ -s $log4j_vulnerable_libs ] || [ -s $log4j_logs_attack ]
then
        echo  "\n[FOUND] log4j is present on the system"
else
        echo "\n[ABSENT] log4j not found on the system"
fi

echo "[REPORT] Full Report is available @ $log4j_full_report"
}

log4j_check
