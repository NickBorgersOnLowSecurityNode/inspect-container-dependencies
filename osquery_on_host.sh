#!/bin/bash
# Fail hard if any problem
set -e
# Load configuration
source ${BASH_SOURCE%/*}/configuration.sh
# Stop (so remove) any past execution
docker stop vulnerable-openssl || true
# Start OpenSSL with long-running task (speed test)
docker run --rm --detach --name vulnerable-openssl ${VULNERABLE_OPENSSL_CONTAINER_IMAGE} openssl speed
# Sleep long enough for OpenSSL to start its work
sleep 2
# Run osqueryi right on the host (this doesn't succeed)
# This query is from Akamai: https://www.akamai.com/blog/security-research/openssl-vulnerability-how-to-effectively-prepare#query
osqueryd -S "$(cat <<EOF
WITH FIRST_QUERY AS (SELECT DISTINCT
    proc.path,
    proc.cmdline,
    proc.pid as pid,
    mmap.path AS mmap_path
FROM process_memory_map AS mmap
LEFT JOIN processes AS proc USING(pid) GROUP BY mmap_path)
SELECT pid, cmdline, mmap_path
FROM FIRST_QUERY
JOIN yara ON yara.path = FIRST_QUERY.mmap_path
AND sigrule = 'rule openssl_3 {
        strings:
                \$re1 = /OpenSSL\s3\.[0-6]{1}\.[0-9]{1}[a-z]{,1}/

        condition:
                \$re1
}
'
AND yara.count > 0;
EOF
)"
# Stop current execution
docker stop vulnerable-openssl
