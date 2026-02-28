# ---------- Build Stage ----------
FROM dart:stable AS build
WORKDIR /app

COPY pubspec.* ./
RUN dart pub get

COPY . .
# Force fresh resolution - remove any Windows-path artifacts
RUN rm -rf .dart_tool pubspec.lock && dart pub get
RUN dart compile exe bin/server.dart -o bin/server

# ---------- Runtime Stage ----------
FROM debian:bullseye-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/bin/server ./bin/server
COPY --from=build /app/.env ./.env

RUN chmod +x ./bin/server
EXPOSE 8080
CMD ["./bin/server"]