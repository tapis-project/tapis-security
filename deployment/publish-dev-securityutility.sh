#!/bin/bash
# Build and publish dev docker image for SkUtility tool
export TAPIS_ENV=dev
# Determine absolute path to location from which we are running
#  and change to that directory.
export RUN_DIR=$(pwd)
export PRG_RELPATH=$(dirname "$0")
cd "$PRG_RELPATH"/. || exit
export PRG_PATH=$(pwd)
cd "$PRG_PATH"/.. || exit
mvn clean install
mvn -f tapis-securitylib/shaded-pom.xml package
./deployment/build-securityutility.sh
docker push tapis/securityutility:dev
