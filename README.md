# Inspect container dependencies
This started with trying to identify use of OpenSSL 3.0 < 3.0.7 in our environment which includes containerized workloads. There are container-image centric ways of searching, but I wanted to measure directly against our boxes.

## Repo contents

### Natively using OSQuery to seek out instances of yara-matching target
This is represented by [osquery_in_container.sh](osquery_in_container.sh) which actually runs OSQuery inside the container to be inspected.
The yara rule: `/OpenSSL\s3\.[0-6]{1}\.[0-9]{1}[a-z]{,1}/` [from a blog post by Akamai](https://www.akamai.com/blog/security-research/openssl-vulnerability-how-to-effectively-prepare#query) which includes the complete osoquery statement here.

### Moving towards including running containers in the check
This is represented by [osquery_on_host.sh](osquery_on_host.sh) which tries to run from the host and accomplish the scanning against running containers.
This doesn't work yet, this is being shared publicly to get help.

