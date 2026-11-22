FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
COPY src ./src
RUN mkdir -p out && javac -d out src/com/promptwall/*.java

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/out ./out
EXPOSE 8080
CMD ["java", "-cp", "out", "com.promptwall.PromptWallServer"]

