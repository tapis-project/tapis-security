#~/bin/bash

mv /usr/local/tomcat/webapps /usr/local/tomcat/webapps2
mv /usr/local/tomcat/webapps.dist /usr/local/tomcat/webapps
cp /tmp/context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml
#mkdir /usr/local/tomcat/webapps/v3
cp -r /usr/local/tapis/security /usr/local/tomcat/webapps/v3
catalina.sh jpda run

