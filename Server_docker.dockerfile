FROM ubuntu
WORKDIR /app
RUN apt-get update && apt-get install -y gcc
COPY server.c .
RUN gcc -o server server.c
EXPOSE 8080
CMD ["./server"]