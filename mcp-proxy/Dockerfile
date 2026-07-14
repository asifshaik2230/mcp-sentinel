# syntax=docker/dockerfile:1
# MCP-Sentinel Proxy — multi-stage build (Apple Silicon arm64 + amd64)
FROM --platform=$BUILDPLATFORM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q -DskipTests package \
    && mv target/mcp-proxy-*.jar /app/app.jar

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends wget gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system sentinel \
    && useradd --system --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel \
    && mkdir -p /data \
    && chown -R sentinel:sentinel /data /app

COPY --from=build /app/app.jar /app/app.jar
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh \
    && sed -i 's/\r$//' /docker-entrypoint.sh

EXPOSE 8080

ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"
VOLUME ["/data"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/actuator/health | grep -q UP || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
