#!/bin/bash

./gradlew clean build

java -Xms512m -Xmx1024m -Djavax.net.ssl.trustStore=/usr/lib/jvm/java-8-oracle/jre/lib/security/cacerts -jar ./build/libs/OIDCClient-0.0.1-SNAPSHOT.war
