#!/bin/bash

### INFO ###
#
# Author: Jay Szczerkowski
# Date: 2025-05-12
# Description: This script is used to scan Docker images within tykio org for vulnerabilities
#

ORG_NAME="tykio"
OUTPUT_FILE="vulnerabilities.csv"
LOG_FILE="output.log"
IMAGES=$#

function precheck() {
  local MISSING_DEP=0
  log "Checking dependencies ..."

  for dep in curl jq trivy; do
    if ! command -v ${dep} >/dev/null; then
      log " --> ${dep} is NOT installed" ERROR
      ((MISSING_DEP++))
    else
      log "  --> ${dep} is installed"
    fi
  done

  if [ ${MISSING_DEP} -ge 1 ]; then
    log "Install missing dependencies and re-run the script" ERROR
    exit 1
  fi
}

function log() {
  local MESSAGE=$1
  local LOG_LEVEL=$2
  local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
  local RED='\033[0;31m'
  local NC='\033[0m'

  if [ -z ${LOG_LEVEL} ]; then
    LOG_LEVEL="INFO"
  fi

  if [ ${LOG_LEVEL} = "ERROR" ]; then
    echo -e "${TIMESTAMP} [${RED}ERROR${NC}] ${MESSAGE}" | tee -a ${LOG_FILE}
  else
    echo "${TIMESTAMP} [${LOG_LEVEL}] ${MESSAGE}" | tee -a ${LOG_FILE}
  fi
}

if [ ${IMAGES} -lt 1 ]; then
  log "Usage: $0 image1 image2 ..." ERROR
  exit 1
fi

# Run precheck
precheck
log "Scanning ${IMAGES} images ..."

# Prepare temp JSON
JSON_TEMP=$(
  for NAME in "$@"; do
    IMAGE="${ORG_NAME}/${NAME}"
    TAG=$(curl -s "https://hub.docker.com/v2/repositories/${IMAGE}/tags?page_size=100" | jq -r 'select(.results != null) | .results | sort_by(.last_updated) | reverse | .[0].name')
    log "  --> ${IMAGE} (${TAG}) ..." >&2
    
    if [ -z ${TAG} ]; then
      log "    --> No valid tags found or image does not exist" ERROR >&2
      continue
    fi

    TRIVY_OUTPUT=$(trivy image --quiet --format json ${IMAGE}:${TAG} 2>/dev/null)
    
    if [ $? -ne 0 ]; then
      log "    --> Something went wrong. Run 'trivy image ${IMAGE}:${TAG}' to see the error" ERROR >&2
    fi 

    echo ${TRIVY_OUTPUT} | jq --arg IMAGE "$IMAGE" '.Results[] | select(.Vulnerabilities != null) | .Vulnerabilities[] | [.PkgName, .Severity, .InstalledVersion, .FixedVersion, .Description, .VulnerabilityID, $IMAGE]'
  done
)

# Generate CSV
log "Aggregating ..."
echo "Package Name,Severity,Installed Version,Fixed Version,Description,CVE ID,Source" > ${OUTPUT_FILE}
echo ${JSON_TEMP} | jq -s '
  group_by([.[0], .[5]]) |
  map({
    pkg: .[0][0],
    severity: .[0][1],
    version: .[0][2],
    fixed: .[0][3],
    desc: (.[0][4] | tostring |  gsub(","; "")),
    cve: .[0][5],
    sources: (map(.[6]) | unique | join(" & "))
  }) |
  map([
    .pkg, .severity, .version, .fixed, .desc, .cve, .sources
  ]) | .[] | @csv
' | sed 's/[\\"]//g' >> ${OUTPUT_FILE}

log "Results in: ${OUTPUT_FILE}"
