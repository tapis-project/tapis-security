#!/bin/bash
export TAPIS_VERSION=
export TAPIS_ENV=dev
cd ..
mvn clean install
mvn -f tapis-securitylib/shaded-pom.xml package
./deployment/build-securityutility.sh 
docker push tapis/securityutility:${TAPIS_ENV}

