# FROM eclipse-temurin:17-jre
# WORKDIR /app
# COPY target/identity-provider-1.0.0.jar app.jar
# COPY src/main/resources/application.properties application.properties
# COPY src/main/resources/application-prod.properties application-prod.properties
# EXPOSE 8080
# ENTRYPOINT ["java", "-jar", "app.jar"]


FROM eclipse-temurin:17-jdk-alpine

# Copy the JAR into the image
COPY target/identity-provider-1.0.0.jar /app.jar

WORKDIR /app
COPY target/identity-provider-1.0.0.jar /app.jar
COPY .env .env
EXPOSE 8080
# Set entrypoint
ENTRYPOINT ["java","-jar","/app.jar"]