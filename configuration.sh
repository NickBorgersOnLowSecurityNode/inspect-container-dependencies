if ! command -v osqueryi &> /dev/null
then
    echo "Must have osqueryi available, please install it and put it on your PATH"
    exit
fi

VULNERABLE_OPENSSL_CONTAINER_IMAGE=clojure:temurin-17-lein-2.9.8-jammy
OSQUERY_QUERY_FOR_SAME_NAMESPACE=$(cat <<EOF
WITH FIRST_QUERY AS (SELECT DISTINCT
    proc.path,
    proc.cmdline,
    proc.pid,
    mmap.path AS mmap_path
FROM process_memory_map AS mmap
LEFT JOIN processes AS proc USING(pid))
SELECT pid, cmdline, mmap_path
FROM FIRST_QUERY
JOIN yara ON yara.path = FIRST_QUERY.mmap_path
WHERE sigrule = 'rule openssl_3 {
        strings:
                \$re1 = /OpenSSL\s3\.[0-6]{1}\.[0-9]{1}[a-z]{,1}/

        condition:
                \$re1
}
'
AND yara.count > 0;
EOF
)
