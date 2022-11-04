# Inspect container dependencies
This started with trying to identify use of OpenSSL 3.0 < 3.0.7 in our environment which includes containerized workloads. There are container-image centric ways of searching, but I wanted to measure directly against our boxes.

## Repo contents

### Natively using OSQuery to seek out instances of yara-matching target
This is represented by [osquery_in_container.sh](osquery_in_container.sh) which actually runs OSQuery inside the container to be inspected.
The yara rule: `/OpenSSL\s3\.[0-6]{1}\.[0-9]{1}[a-z]{,1}/` [from a blog post by Akamai](https://www.akamai.com/blog/security-research/openssl-vulnerability-how-to-effectively-prepare#query) which includes the complete osoquery statement here.

The output of this script will be like:
```
nborgers@devrestricted-nborgers:~/code/inspect-container-dependencies$ ./osquery_in_container.sh
Error response from daemon: No such container: vulnerable-openssl
46bb8f2f8da622e2d643f3d3d86b734fed776d290ac2847052cb4c62a01347bf
+-----+---------------+------------------------------------------+
| pid | cmdline       | mmap_path                                |
+-----+---------------+------------------------------------------+
| 7   | openssl speed | /usr/bin/openssl                         |
| 7   | openssl speed | /usr/lib/x86_64-linux-gnu/libcrypto.so.3 |
+-----+---------------+------------------------------------------+
vulnerable-openssl
```

The procedure was:
1. Kill any leftover container from a previous run of either script
1. Start version of OpenSSL which matches the yara rule in a Docker container, it stays running for a while running a speed test
1. Run complex OSQuery to look for matching libraries, specifically:
  1. Enumerate all processes
  1. Enumerate their memory maps
  1. Run the yara rule against all the paths indicated in the memory map
1. Stop the OpenSSL process and container

### Moving towards including running containers in the check
This is represented by [osquery_on_host.sh](osquery_on_host.sh) which tries to run from the host and accomplish the scanning against running containers.
This uses the same yara rule from Akamai but is an attempt to run this for all processes on a given host including Docker containers.

The output of this script will be like:
```
nborgers@devrestricted-nborgers:~/code/inspect-container-dependencies$ ./osquery_on_host.sh
Error response from daemon: No such container: vulnerable-openssl
b44ce18671a5af1d11695135f1d7337a6769bb4db0d52c59644cb3b91b3744a9
+--------------------------------------------------------------------------------------------------------------+-----------+
| path                                                                                                         | matches   |
+--------------------------------------------------------------------------------------------------------------+-----------+
| /mnt/docker/overlay2/340988206c1674125bb0c25aa27ddbde90eb1e1b11f40366c8e1586cc5c0e7a6/merged/usr/bin/openssl | openssl_3 |
+--------------------------------------------------------------------------------------------------------------+-----------+
+--------------------------------------------------------------------------------------------------------------------------------------+-----------+
| path                                                                                                                                 | matches   |
+--------------------------------------------------------------------------------------------------------------------------------------+-----------+
| /mnt/docker/overlay2/340988206c1674125bb0c25aa27ddbde90eb1e1b11f40366c8e1586cc5c0e7a6/merged/usr/lib/x86_64-linux-gnu/libcrypto.so.3 | openssl_3 |
+--------------------------------------------------------------------------------------------------------------------------------------+-----------+
vulnerable-openssl
```

The procedure was:
1. Kill any leftover container from a previous run of either script
1. Start version of OpenSSL which matches the yara rule in a Docker container, it stays running for a while running a speed test
1. Cheat by getting pid based on process name (real objective is to enumerate all processes as before, but am focused on pivoting to container)
1. Read the `/proc/$pid/mountinfo` for the container process to extract directory name
1. Use regexes to trim that down
1. Run OSQuery to get the memory map for the container `pid`
1. Iterative over all results in the memory map for the container `pid`
  1. Combine the container directory path + `/merged` + memory map path to get the actual files identified as loaded into the process memory
  1. Run the yara rule against each actual file on the local filesystem which was loaded into memory by the containerized process
1. Stop the OpenSSL process and container

