# Set mosquitto and plugin version
ARG MOSQUITTO_VERSION=2.0.18
ARG OAUTH_PLUGIN_VERSION=1.0.0

FROM alpine:3.20
ARG MOSQUITTO_VERSION
ARG OAUTH_PLUGIN_VERSION

# Install necessary build dependencies
RUN apk update && apk add --no-cache --virtual build-deps \
    build-base \
    cmake \
    openssl-dev \
    cjson-dev \
    libwebsockets-dev \
    curl-dev \
    jansson-dev \
    libjwt-dev

# Build mosquitto from source
RUN wget http://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz
RUN tar xzvf mosquitto-${MOSQUITTO_VERSION}.tar.gz
RUN cd mosquitto-${MOSQUITTO_VERSION} \
    && make WITH_WEBSOCKETS=yes WITH_ADNS=no WITH_DOCS=no WITH_SRV=no prefix=/usr \
    && make install \
    && cd .. \
    && rm -rf mosquitto-${MOSQUITTO_VERSION} mosquitto-${MOSQUITTO_VERSION}.tar.gz 

# Build the mosquitto-oauth-plugin from source
RUN wget https://github.com/iotinga/mosquitto-oauth-plugin/archive/refs/tags/v${OAUTH_PLUGIN_VERSION}.tar.gz -O mosquitto-oauth-plugin-${OAUTH_PLUGIN_VERSION}.tar.gz
RUN tar xzvf mosquitto-oauth-plugin-${OAUTH_PLUGIN_VERSION}.tar.gz
RUN cd mosquitto-oauth-plugin-${OAUTH_PLUGIN_VERSION} \
    && mkdir build && cd build \
    && cmake .. \
    && make \
    && make install \
    && cd .. \
    && rm -rf mosquitto-oauth-plugin-${OAUTH_PLUGIN_VERSION} mosquitto-oauth-plugin-${OAUTH_PLUGIN_VERSION}.tar.gz

# Remove build dependencies
RUN apk del build-deps

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    cjson \
    libressl \
    libwebsockets \
    curl \
    jansson \
    libjwt 

# Create mosquitto directories
RUN mkdir -p /mosquitto/config /mosquitto/data /mosquitto/log

# Create mosquitto system user
RUN addgroup -S mosquitto \
    && adduser -S -D -H -s /sbin/nologin -G mosquitto -g mosquitto mosquitto \
    && chown -R mosquitto:mosquitto /mosquitto

# Add default configuration
COPY mosquitto-example.conf /mosquitto/config/mosquitto.conf

# Set up entry point
VOLUME ["/mosquitto/data", "/mosquitto/log"]
EXPOSE 1883
CMD ["/usr/local/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]