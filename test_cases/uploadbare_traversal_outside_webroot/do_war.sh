FILENAME=uploadbare_traversal_outside_webroot.war
# BUILD
javac -cp .:/usr/share/java/tomcat8-servlet-api.jar UploadServlet.java
cp UploadServlet.class WEB-INF/classes/
jar cfv $FILENAME message.jsp upload.jsp WEB-INF/ META-INF/ images/

# DEPLOY (tomcat8-specific paths)
cp -v $FILENAME /var/lib/tomcat8/webapps
chmod a+r /var/lib/tomcat8/webapps/$FILENAME
/etc/init.d/tomcat8 stop
/etc/init.d/tomcat8 start

