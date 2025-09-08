# FROM eclipse-temurin:17-jre
# WORKDIR /app
# COPY target/identity-provider-1.0.0.jar app.jar
# COPY src/main/resources/application.properties application.properties
# COPY src/main/resources/application-prod.properties application-prod.properties
# EXPOSE 8080
# ENTRYPOINT ["java", "-jar", "app.jar"]

FROM eclipse-temurin:17-jre
# Set working directory
WORKDIR /app

# Copy the fat jar
COPY target/identity-provider-1.0.0.jar app.jar

# Copy optional environment variables
COPY .env .env

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]