FROM existdb/existdb:6.4.1

COPY exist-oidc/target/exist-oidc-realm-0.1.0-SNAPSHOT.jar /exist/lib/user/exist-oidc-realm-0.1.0-SNAPSHOT.jar
COPY demo/existdb/web.xml /exist/etc/webapp/WEB-INF/web.xml
COPY demo/existdb/oidc.properties /exist/etc/oidc.properties
COPY demo/existdb/*.xar /exist/autodeploy
COPY demo/existdb/install-security-config.xql /tmp/install-security-config.xql
COPY demo/existdb/config.xml /tmp/config.xml

ENV JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS} -Dorg.exist.webdav.PROPFIND_METHOD_XML_SIZE=EXACT -Dorg.exist.webdav.GET_METHOD_XML_SIZE=NULL"
ENV CLASSPATH="${CLASSPATH}:/exist/lib/user/*"

# RUN ["java", "-Dorg.exist.webdav.PROPFIND_METHOD_XML_SIZE=EXACT", "-Dorg.exist.webdav.GET_METHOD_XML_SIZE=NULL", "org.exist.start.Main", "client", "-l", "-s", "-u", "admin", "-P", "", "-F", "/tmp/install-security-config.xql"]
RUN ["java", \
     "-Dorg.exist.webdav.PROPFIND_METHOD_XML_SIZE=EXACT", \
     "-Dorg.exist.webdav.GET_METHOD_XML_SIZE=NULL", \
     "org.exist.start.Main", \
     "client", \
     "-l", \
     "-s", \
     "-u", "admin", \
     "-P", "", \
     "-F", "/tmp/install-security-config.xql"]