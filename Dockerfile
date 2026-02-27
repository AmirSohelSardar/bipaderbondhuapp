# ---------- Build Stage ----------
FROM dart:stable AS build
WORKDIR /app

COPY pubspec.* ./
RUN dart pub get

COPY . .
RUN dart compile exe bin/server.dart -o bin/server

# ---------- Runtime Stage ----------
FROM debian:bullseye-slim
WORKDIR /app

COPY --from=build /app/bin/server ./bin/server
COPY --from=build /app/.env ./.env

EXPOSE 8080
CMD ["./bin/server"]