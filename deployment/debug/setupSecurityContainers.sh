#!/bin/bash
#set -xv

function missingVarMessage() {
    echo A required variable \'$1\' is missing
    exit 1
}

function setVars() {
    if [[ ! ${PG_PORT} ]] ; then
        missingVarMessage "PG_PORT" 
    else 
        export PG_PORT
        echo PG_PORT = ${PG_PORT}
    fi

    if [[ ! ${PG_USER_NAME} ]] ; then
        missingVarMessage "PG_USER_NAME"
    else 
        export PG_USER_NAME
        echo PG_USER_NAME = ${PG_USER_NAME}
    fi

    if [[ ! ${PG_USER_PASSWORD} ]] ; then
        missingVarMessage "PG_USER_PASSWORD"
    else 
        export PG_USER_PASSWORD
        echo PG_USER_PASSWORD = ${PG_USER_PASSWORD}
    fi

    if [[ ! ${PG_ADMIN_NAME} ]] ; then
        missingVarMessage "PG_ADMIN_NAME"
    else 
        export PG_ADMIN_NAME
        echo PG_ADMIN_NAME = ${PG_ADMIN_NAME}
    fi

    if [[ ! ${PG_ADMIN_PASSWORD} ]] ; then
        missingVarMessage "PG_ADMIN_PASSWORD"
    else 
        export PG_ADMIN_PASSWORD
        echo PG_ADMIN_PASSWORD = ${PG_ADMIN_PASSWORD}
    fi

    if [[ ! ${VAULT_ADDRESS} ]] ; then
        missingVarMessage "VAULT_ADDRESS"
    else 
        export VAULT_ADDRESS
        echo VAULT_ADDRESS = ${VAULT_ADDRESS}
    fi

    if [[ ! ${VAULT_CONFIG_DIR} ]] ; then
        missingVarMessage "VAULT_CONFIG_DIR"
    else 
        export VAULT_CONFIG_DIR
        echo VAULT_CONFIG_DIR = ${VAULT_CONFIG_DIR}
    fi

    #set as part of the init process
    export VAULT_ROLE_ID
    echo VAULT_ROLE_ID = ${VAULT_ROLE_ID}

    #set as part of the init process
    export VAULT_SECRET_ID
    echo VAULT_SECRET_ID = ${VAULT_SECRET_ID}
}

function announce() {
  echo ---==== $@ ====---
}

function readConfig() {
  source ${CONFIG_FILE}
  setVars
}

function doVault() {
  readConfig
  announce "Docker compose down"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml up -d tapis-security-vault
}

function doDown() {
  readConfig
  announce "Docker compose down"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml down
}

function doStart() {
  readConfig
  announce "Docker compose start"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml start 
}

function doUp() {
  readConfig
  announce "Docker compose up"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml up -d
}

function doStop() {
  readConfig
  announce "Docker compose stop"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml stop
}

function doRestart() {
  readConfig
  announce "Docker compose restart"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml restart
}

function doInit() {
  if [[ -f ${CONFIG_FILE} ]] ; then
      echo -n 'Config already exists.  Are you sure you want to overwrite it (y/N)?'
      read -r OVERWRITE
      echo
      OVERWRITE=${OVERWRITE^^}
      if [[ ! ${OVERWRITE} == "Y" ]] && [[ ! ${OVERWRITE} == "YES" ]] ; then
        echo Not overwritting file ...
        exit 1
      fi
  fi

  cp ${SCRIPT_DIR}/${CONFIG_TEMPLATE} ${SCRIPT_DIR}/${CONFIG_FILE}

  readConfig

  announce "starting postgres"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml up tapis-security-postgres --wait

  announce "starting vault"
  docker compose -f ${SCRIPT_DIR}/docker-compose.yml up tapis-security-vault --wait

  announce "Attempting to get vault token"
  #docker exec -i tapis-security-vault /bin/sh -c "export VAULT_ADDR='http://127.0.0.1:8200' ;vault operator init > /tmp/vault-init" 
  docker exec -i tapis-security-vault /bin/sh -c "vault operator init > /tmp/vault-init" 

  VAULT_TOKEN=`docker exec -i tapis-security-vault /bin/sh -c "cat /tmp/vault-init" | grep "Root Token" | sed -E "s/.*Root Token[[:space:]]*:[[:space:]]*//"`
  VAULT_UNSEAL_KEY1=`docker exec -i tapis-security-vault /bin/sh -c "cat /tmp/vault-init" | grep "Unseal Key 1" | sed -E "s/Unseal Key 1[[:space:]]*:[[:space:]]*//"`
  VAULT_UNSEAL_KEY2=`docker exec -i tapis-security-vault /bin/sh -c "cat /tmp/vault-init" | grep "Unseal Key 2" | sed -E "s/Unseal Key 2[[:space:]]*:[[:space:]]*//"`
  VAULT_UNSEAL_KEY3=`docker exec -i tapis-security-vault /bin/sh -c "cat /tmp/vault-init" | grep "Unseal Key 3" | sed -E "s/Unseal Key 3[[:space:]]*:[[:space:]]*//"`
  VAULT_UNSEAL_KEY4=`docker exec -i tapis-security-vault /bin/sh -c "cat /tmp/vault-init" | grep "Unseal Key 4" | sed -E "s/Unseal Key 4[[:space:]]*:[[:space:]]*//"`
  VAULT_UNSEAL_KEY5=`docker exec -i tapis-security-vault /bin/sh -c "cat /tmp/vault-init" | grep "Unseal Key 5" | sed -E "s/Unseal Key 5[[:space:]]*:[[:space:]]*//"`

#  for attempt in {1..5}; do
#      announce "Attempting to get vault token"
#      VAULT_TOKEN=`docker exec -i tapis-security-vault /bin/sh -c "cat /tmp/vault-init" | grep "Root Token" | sed -E "s/Root Token[[:space:]]*:[[:space:]]*//"`
#      if [[ -z ${VAULT_TOKEN} ]] ; then
#          sleep 1;
#      else
#          break;
#      fi
#  done;

  if [[ -z ${VAULT_TOKEN} ]] ; then
     echo VAULT TOKEN could not be found
     exit 1
  fi

  echo VAULT_TOKEN=${VAULT_TOKEN} >> ${CONFIG_FILE}
  echo VAULT_UNSEAL_KEY1=${VAULT_UNSEAL_KEY1} >> ${CONFIG_FILE}
  echo VAULT_UNSEAL_KEY2=${VAULT_UNSEAL_KEY2} >> ${CONFIG_FILE}
  echo VAULT_UNSEAL_KEY3=${VAULT_UNSEAL_KEY3} >> ${CONFIG_FILE}
  echo VAULT_UNSEAL_KEY4=${VAULT_UNSEAL_KEY4} >> ${CONFIG_FILE}
  echo VAULT_UNSEAL_KEY5=${VAULT_UNSEAL_KEY5} >> ${CONFIG_FILE}

#  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_ADDR='http://127.0.0.1:8200' ;vault operator unseal ${VAULT_UNSEAL_KEY1}" 
#  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_ADDR='http://127.0.0.1:8200' ;vault operator unseal ${VAULT_UNSEAL_KEY2}" 
#  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_ADDR='http://127.0.0.1:8200' ;vault operator unseal ${VAULT_UNSEAL_KEY3}" 
#  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_ADDR='http://127.0.0.1:8200' ;vault operator unseal ${VAULT_UNSEAL_KEY4}" 
#  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_ADDR='http://127.0.0.1:8200' ;vault operator unseal ${VAULT_UNSEAL_KEY5}" 
  docker exec -i tapis-security-vault /bin/sh -c "vault operator unseal ${VAULT_UNSEAL_KEY1}" 
  docker exec -i tapis-security-vault /bin/sh -c "vault operator unseal ${VAULT_UNSEAL_KEY2}" 
  docker exec -i tapis-security-vault /bin/sh -c "vault operator unseal ${VAULT_UNSEAL_KEY3}" 
  docker exec -i tapis-security-vault /bin/sh -c "vault operator unseal ${VAULT_UNSEAL_KEY4}" 
  docker exec -i tapis-security-vault /bin/sh -c "vault operator unseal ${VAULT_UNSEAL_KEY5}" 

  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_TOKEN=${VAULT_TOKEN} ; vault secrets enable -version=2 -path=secret kv"
  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_TOKEN=${VAULT_TOKEN} ; vault auth enable approle"
  docker exec -i tapis-security-vault /bin/sh -c "export VAULT_TOKEN=${VAULT_TOKEN} ; vault auth enable userpass"

  http ${VAULT_ADDRESS}/v1/sys/health X-Vault-Token:${VAULT_TOKEN}
  http ${VAULT_ADDRESS}/v1/auth/approle/role/sk X-Vault-Token:${VAULT_TOKEN} < ${VAULT_CONFIG_DIR}/roles/sk-role.json
  http ${VAULT_ADDRESS}/v1/auth/approle/role/sk-admin X-Vault-Token:${VAULT_TOKEN} < ${VAULT_CONFIG_DIR}/roles/sk-admin-role.json

  pushd ${VAULT_CONFIG_DIR}
  ./CreatePolicies.sh  -t $VAULT_TOKEN -h localhost --http
  popd

  http ${VAULT_ADDRESS}/v1/auth/token/create displayname="tapisroot" ttl:=0 policies:='["root"]' X-Vault-Token:${VAULT_TOKEN}

#  VAULT_ROLE_ID=$(http ${VAULT_ADDRESS}/v1/auth/approle/role/sk/role-id X-Vault-Token:${VAULT_TOKEN} | jq -r ".data.role_id")
#  VAULT_SECRET_ID=$(echo | http POST ${VAULT_ADDRESS}/v1/auth/approle/role/sk/secret-id X-Vault-Token:${VAULT_TOKEN} | jq -r ".data.secret_id")

  echo VAULT_ROLE_ID=$(http ${VAULT_ADDRESS}/v1/auth/approle/role/sk/role-id X-Vault-Token:${VAULT_TOKEN} | jq -r ".data.role_id") >> ${CONFIG_FILE}
  echo VAULT_SECRET_ID=$(echo | http POST ${VAULT_ADDRESS}/v1/auth/approle/role/sk/secret-id X-Vault-Token:${VAULT_TOKEN} | jq -r ".data.secret_id") >> ${CONFIG_FILE}

  announce "setup database"
  java -jar ../../tapis-securitymigrate/target/securitymigrate.jar -h localhost -p ${PG_PORT} -u ${PG_ADMIN_NAME} -pw ${PG_ADMIN_PASSWORD} -tpw ${PG_USER_PASSWORD}

  doUp
}

SCRIPT_DIR=$(dirname $0)
SERVICE_CODE="security"
CONFIG_TEMPLATE=${SCRIPT_DIR}/security.conf
CONFIG_FILE=${SCRIPT_DIR}/security.conf.current

if [[ ! $#  -eq 1 ]] ; then
  echo must provide a command
  exit  1
fi

COMMAND=$1

case $COMMAND in
  init)
    doInit
    ;;
  down)
    doDown
    ;;
  stop)
    doStop
    ;;
  start)
    doStart
    ;;
  up)
    doUp
    ;;
  restart)
    doRestart
    ;;
  vault)
    doVault
    ;;
  *)
    echo "Unknown command '$COMMAND'"
    exit 1
esac

exit 0



announce "starting rabbitmq"
docker compose -f ${SCRIPT_DIR}/docker-compose.yml up tapis-security-rabbitmq --wait


announce "Start security environment"
docker compose up -d

