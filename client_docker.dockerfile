FROM gcc:latest
WORKDIR /app
COPY client.c .
RUN gcc -o client client.c
CMD ["./client"]