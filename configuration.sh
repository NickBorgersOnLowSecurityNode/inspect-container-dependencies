if ! command -v osqueryi &> /dev/null
then
    echo "Must have osqueryi available, please install it and put it on your PATH"
    exit
fi

VULNERABLE_OPENSSL_CONTAINER_IMAGE=clojure:temurin-17-lein-2.9.8-jammy
