ROPFUSCATOR_PATH=`( cd $(dirname $0) && cd .. && pwd )`

docker build -q -t tigress $ROPFUSCATOR_PATH/docker/tigress
docker cp `docker create tigress`:/opt/tigress/tigress_samples.tar.gz .