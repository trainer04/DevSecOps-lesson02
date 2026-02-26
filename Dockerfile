FROM adoptopenjdk:11-jre-hotspot

# VULN: Running as root
USER root

# VULN: Hardcoded credentials in Dockerfile
ENV DB_PASSWORD="SuperSecret123!"
ENV ADMIN_PASSWORD="admin123"

# Create app directory
WORKDIR /app

# Copy JAR file
COPY target/*.jar app.jar

# VULN: Exposing debug port
EXPOSE 8080 5005

# VULN: Running with root privileges
ENTRYPOINT ["java", "-jar", "app.jar"]

# VULN: No health check
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD curl -f http://localhost:8080/actuator/health || exit 1