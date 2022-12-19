#!/bin/bash
# Fail hard if any problem
set -e
# Load configuration
source ${BASH_SOURCE%/*}/configuration.sh
# Stop (so remove) any past execution
docker stop vulnerable-openssl || true
# Start OpenSSL with long-running task (speed test)
docker run --rm --detach --name vulnerable-openssl \
  ${VULNERABLE_OPENSSL_CONTAINER_IMAGE} openssl speed
# Sleep long enough for OpenSSL to start its work
sleep 2
# Get OpenSSL pid
pid=$(pgrep openssl)
# Get directory of pid's mount namespace
overall_config_line=$(grep overlay /proc/$pid/mountinfo)
# This regex rips out the workdir part
just_workdir_line=$(echo $overall_config_line | grep -Po 'workdir=([a-zA-Z0-9\/].*)(?=\/[a-z].+,)')
# This gets only the match group (removes the workdir= we keyed off but didn't want)
just_directory=$(echo $just_workdir_line | grep -Po '\/.*')
# Run OSQuery to get matching mmap_paths
memory_map_paths=$(sudo osqueryi --header=false --csv --separator ',' "$(cat <<EOF
SELECT DISTINCT
    path
FROM process_memory_map WHERE pid = ${pid} GROUP BY path
EOF
)")

# Iterate over lines of output from osquery
while IFS= read -r this_memory_map_path; do
    # If the first character isn't a [ or " we assume this is a file
    if [[ ${this_memory_map_path::1} != "[" && ${this_memory_map_path::1} != "\"" ]]
    then
        # Combine our file path ingredients
        actual_file_loaded_in_memory_by_process="${just_directory}/merged${this_memory_map_path}"
	# Use OSqueryi to invoke the yara rule against this file, note we have to add /merged between the directory and path from the memory map
        sudo osqueryi -S "$(cat <<EOF
SELECT path, matches FROM yara WHERE path = "${actual_file_loaded_in_memory_by_process}" AND
sigrule = 'rule openssl_3 {
        strings:
                \$re1 = /OpenSSL\s3\.[0-6]{1}\.[0-9]{1}[a-z]{,1}/

        condition:
                \$re1
 }
'
AND count > 0;
EOF
)"
    fi
done <<< "${memory_map_paths}"

# Stop current execution
docker stop vulnerable-openssl
