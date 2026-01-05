FROM ubuntu:20.04

# VULNERABILITY: Use of ADD instead of COPY (Rule DKR-003)
ADD ./target/myapp.jar /app/myapp.jar

# VULNERABILITY: Hardcoded Secret in ENV (Rule DKR-004)
ENV DB_PASSWORD=super_secret_password_123

# VULNERABILITY: Exposed SSH Port (Rule DKR-002)
EXPOSE 22
EXPOSE 8080

CMD ["java", "-jar", "/app/myapp.jar"]

# VULNERABILITY: Missing USER instruction (Rule DKR-001)
# (Scanner will flag the whole file because 'USER' is missing)