FROM eclipse-temurin:21-jre
WORKDIR /app
RUN groupadd -r aegis && useradd -r -g aegis aegis
COPY build/libs/AegisPassport-BackEnd-*.jar app.jar
RUN mkdir -p /app/uploads && chown -R aegis:aegis /app
USER aegis
EXPOSE 8421
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
