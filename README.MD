########################################################################################
#################### Version 2.0 | Hardening script RHEL8 & RHEL9#######################
########################################################################################
Pre-requisites: 
---------------
Please take a latest snapshot backup of VM before run the script.
 
Install the below package:
-------------------------
#rpm -qa | grep -i ansible
ansible-core-2.14.2-4.el9.x86_64
 
Make sure the version:
-----------------------
# ansible --version
ansible [core 2.14.2]
config file = /etc/ansible/ansible.cfg
configured module search path = ['/root/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
ansible python module location = /usr/lib/python3.11/site-packages/ansible
ansible collection location = /root/.ansible/collections:/usr/share/ansible/collections
executable location = /usr/bin/ansible
python version = 3.11.2 (main, Feb 16 2023, 00:00:00) [GCC 11.3.1 20221121 (Red Hat 11.3.1-4)] (/usr/bin/python3.11)
jinja version = 3.1.2
libyaml = True
 
#Make sure the following python3.11 or 3.9 installed
----------------------------------------------------
[root@ocp-devops-node-01 ~]# py
pydoc       pydoc3      pydoc3.11   pydoc3.9    pyinotify   python      python3     python3.11  python3.9

####################commands to run in each versions###########################

Command to execute the script 
------------------------------

 For RHEL8.8 or above
 # ansible-playbook -i inventory hardening.yml -e "BUILD_METHOD=hardening-rhel8"
 for RHEL8.7 or below
 # ansible-playbook -i inventory hardening.yml -e "BUILD_METHOD=hardening-rhel8" -e "RHEL_VERSION=8.7" 
 for RHEL9.2 or above
 # ansible-playbook -i inventory hardening.yml -e "BUILD_METHOD=hardening-rhel9" -e
 for RHEL9.1 
 # ansible-playbook -i inventory hardening.yml -e "BUILD_METHOD=hardening-rhel9" -e "RHEL_VERSION=9.1"