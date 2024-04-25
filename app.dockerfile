
FROM openjdk:17-jdk-alpine

WORKDIR /app

LABEL description="Application Image"
LABEL version="1.0"

COPY target/security-0.0.1-SNAPSHOT.jar /app/security.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "security.jar"]