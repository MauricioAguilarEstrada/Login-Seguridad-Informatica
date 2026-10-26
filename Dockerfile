# Etapa de compilación
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

# Etapa de ejecución
FROM eclipse-temurin:25-jre
WORKDIR /app
# Filtramos específicamente el archivo que termina en SNAPSHOT.jar
COPY --from=build /app/target/*-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-Djava.net.preferIPv4Stack=true", "-jar", "app.jar"]