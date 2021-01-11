FROM ubuntu:14.04

ENV JDK_INSTALL_BIN="j2sdk-1_4_2_19-linux-i586.bin" \
    TOMCAT_ZIP="jakarta-tomcat-5.0.25.zip" \
    JAVA_HOME="/opt/jdk" \
    CATALINA_HOME="/opt/tomcat"

COPY ${JDK_INSTALL_BIN} /opt/
COPY ${TOMCAT_ZIP} /opt/
COPY ROOT.war /root/
COPY check_process.sh /root/
COPY flag /flag

RUN set -ex \
    && dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y lib32z1 zip acl libxt6:i386 libxext6:i386 libxtst6:i386 libbsd0:i386 libc6:i386 libfontconfig1:i386 libfreetype6:i386 libpng12-0:i386 libx11-6:i386 libxau6:i386 libxcb1:i386 libxcomposite1:i386 libxdmcp6:i386 libxi6:i386 libxinerama1:i386 libxrandr2:i386 libxrender1:i386 \
    && cd /opt/ \
    && chmod u+x ${JDK_INSTALL_BIN} \
    && yes yes | ./${JDK_INSTALL_BIN} \
    && mv j2sdk1.4.* ${JAVA_HOME} \
    && update-alternatives --install /usr/bin/java java /opt/jdk/bin/java 100 \
    && update-alternatives --install /usr/bin/javac javac /opt/jdk/bin/javac 100 \
    && update-alternatives --install /usr/bin/jar jar /opt/jdk/bin/jar 100 \
    && rm -rf /opt/${JDK_INSTALL_BIN} \
    && unzip ${TOMCAT_ZIP} \
    && rm -rf /opt/${TOMCAT_ZIP} \
    && mv *-tomcat-* ${CATALINA_HOME} \
    && cd ${CATALINA_HOME} \
    && rm -rf webapps/* \
    && rm -rf conf/Catalina/localhost/* \
    && rm -rf server/webapps/* \
    && sed -i '35a <!--' conf/server.xml \
    && sed -i '50a -->' conf/server.xml \
    && sed -i '174a <!--' conf/server.xml \
    && sed -i '177a -->' conf/server.xml \
    && mkdir webapps/ROOT \
    && unzip /root/ROOT.war -d webapps/ROOT/ \
    && groupadd ctf && useradd -g ctf ctf \
    && chgrp -R ctf ${CATALINA_HOME} \
    && chmod g+w logs/ work/ temp/ \
    && chmod g+s webapps/ logs/ work/ temp/ \
    && setfacl -d -m group:ctf:rwx /opt/tomcat/work /opt/tomcat/temp /opt/tomcat/logs \
    && chmod ug+x bin/*.sh \
    && (echo "* * * * * root /bin/bash /root/check_process.sh" > /etc/cron.d/check-process) \
    && chmod 0644 /etc/cron.d/check-process \
    && rm -rf /var/lib/apt/lists/*

CMD cron && su ctf -c "sh ${CATALINA_HOME}/bin/catalina.sh run"
