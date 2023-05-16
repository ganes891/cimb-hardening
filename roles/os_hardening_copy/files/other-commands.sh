#!/bin/bash
AUDITDIR="/var/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"
. /etc/os-release
MAIN_VERSION_ID="$(echo ${VERSION_ID} |cut -f1 -d'.')"
if [[ ${MAIN_VERSION_ID} -lt 8 ]]; then
  echo "OS release lower than 8 not supported. You are running ${VERSION_ID}"
fi