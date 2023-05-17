#!/bin/bash
AUDITDIR="/var/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"
. /etc/os-release
MAIN_VERSION_ID="$(echo ${VERSION_ID} |cut -f1 -d'.')"
if [[ ${MAIN_VERSION_ID} -lt 9 ]]; then
  echo "OS release lower than 9 not supported. You are running ${VERSION_ID}"
fi

mkdir -p $AUDITDIR
echo "Creating Banner..."
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
/------------------------------------------------------------------------\
|                       *** NOTICE TO USERS ***                          |
|                                                                        |
| This computer system is the private property of RHB Bank      |
| It is for authorized use only.                                         |
|                                                                        |
| Users (authorized or unauthorized) have no explicit or implicit        |
| expectation of privacy.                                                |
|                                                                        |
| Any or all uses of this system and all files on this system may be     |
| intercepted, monitored, recorded, copied, audited, inspected, and      |
| disclosed to your employer, to authorized site, government, and law    |
| enforcement personnel, as well as authorized officials of government   |
| agencies, both domestic and foreign.                                   |
|                                                                        |
| By using this system, the user consents to such interception,          |
| monitoring, recording, copying, auditing, inspection, and disclosure   |
| at the discretion of such personnel or officials.  Unauthorized or     |
| improper use of this system may result in civil and criminal penalties |
| and administrative or disciplinary action, as appropriate. By          |
| continuing to use this system you indicate your awareness of and       |
| consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
| you do not agree to the conditions stated in this warning.             |
\------------------------------------------------------------------------/
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
YOUR_COMPANY_NAME AUTHORIZED USE ONLY
EOF
rm -rf /etc/issue
ln -s /etc/issue.net /etc/issue

##################network-changes##################
cat > /etc/sysctl.d/99-sysctl.conf << EOF
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_bold_ignore_broadcasts=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.disable_ipv6=1
fs.suid_dumpable=0
EOF

######################SSH Server Configuration#################################

echo "Configuring SSH related all hardening values - SEC - 5.2"
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
for i in \
"LogLevel INFO" \
"Protocol 2" \
"X11Forwarding no" \
"MaxAuthTries 3" \
"IgnoreRhosts yes" \
"HostbasedAuthentication no" \
"PermitRootLogin yes" \
"PermitEmptyPasswords no" \
"PermitUserEnvironment no" \
"ClientAliveInterval 300" \
"ClientAliveCountMax 3" \
"LoginGraceTime 60" \
"UsePAM yes" \
"MaxStartups 10:30:60" \
"MaxSessions 4" \
"AllowTcpForwarding no" \
"MaxAuthTries 3" \
"Ciphers aes128-ctr,aes192-ctr,aes256-ctr" \
; do
  [[ `egrep -q "^${i}" /etc/ssh/sshd_config` ]] && continue
  option=${i%% *}
  grep -q ${option} /etc/ssh/sshd_config && sed -i "s/.*${option}.*/$i/g" /etc/ssh/sshd_config || echo "$i" >> /etc/ssh/sshd_config
done

chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

###############################SEC- 5.4.5#################################################
echo "Ensure system accounts are secured  - SEC - 5.4.5 "
awk -F: '($1!="root" && $1!="sync" &&  $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd  

echo "Ensure system accounts are secured second command - SEC - 5.4.5"
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' 

