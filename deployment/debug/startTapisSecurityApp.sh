#~/bin/bash

INIT_FILE=".tapisInit" 

if [[ ! -f ${INIT_FILE} ]] ; then 
  mv /usr/local/tomcat/webapps /usr/local/tomcat/webapps2
  mv /usr/local/tomcat/webapps.dist /usr/local/tomcat/webapps
  cp /tmp/context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml
  touch ${INIT_FILE}
fi
#mkdir /usr/local/tomcat/webapps/v3
cp -r /usr/local/tapis/security /usr/local/tomcat/webapps/v3
catalina.sh jpda run

