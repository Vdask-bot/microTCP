/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../lib/microtcp.h"

#define CHUNK_SIZE 4096

static inline void
print_statistics (ssize_t received, struct timespec start, struct timespec end)
{
  double elapsed = end.tv_sec - start.tv_sec
      + (end.tv_nsec - start.tv_nsec) * 1e-9;
  double megabytes = received / (1024.0 * 1024.0);
  printf ("Data received: %f MB\n", megabytes);
  printf ("Transfer time: %f seconds\n", elapsed);
  printf ("Throughput achieved: %f MB/s\n", megabytes / elapsed);
}

int
server_tcp (uint16_t listen_port, const char *file)
{
  uint8_t *buffer;
  FILE *fp;
  int sock;
  int accepted;
  int received;
  ssize_t written;
  ssize_t total_bytes = 0;
  socklen_t client_addr_len;

  struct sockaddr_in sin;
  struct sockaddr client_addr;
  struct timespec start_time;
  struct timespec end_time;

  /* Allocate memory for the application receive buffer */
  buffer = (uint8_t *) malloc (CHUNK_SIZE);
  if (!buffer) {
    perror ("Allocate application receive buffer");
    return -EXIT_FAILURE;
  }

  /* Open the file for writing the data from the network */
  fp = fopen (file, "w");
  if (!fp) {
    perror ("Open file for writing");
    free (buffer);
    return -EXIT_FAILURE;
  }

  if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    perror ("Opening TCP socket");
    free (buffer);
    fclose (fp);
    return -EXIT_FAILURE;
  }

  memset (&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (listen_port);
  /* Bind to all available network interfaces */
  sin.sin_addr.s_addr = INADDR_ANY;

  if (bind (sock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) == -1) {
    perror ("TCP bind");
    free (buffer);
    fclose (fp);
    return -EXIT_FAILURE;
  }

  if (listen (sock, 1000) == -1) {
    perror ("TCP listen");
    free (buffer);
    fclose (fp);
    return -EXIT_FAILURE;
  }

  /* Accept a connection from the client */
  client_addr_len = sizeof(struct sockaddr);
  accepted = accept (sock, &client_addr, &client_addr_len);
  if (accepted < 0) {
    perror ("TCP accept");
    free (buffer);
    fclose (fp);
    return -EXIT_FAILURE;
  }

  /*
   * Start processing the received data.
   *
   * Also start measuring time. Not the most accurate measurement, but
   * it is a good starting point.
   *
   * At hy-435 we deal with bandwidth measurements software in a more
   * right and careful way :-)
   */

  clock_gettime (CLOCK_MONOTONIC_RAW, &start_time);
  while ((received = recv (accepted, buffer, CHUNK_SIZE, 0)) > 0) {
    written = fwrite (buffer, sizeof(uint8_t), received, fp);
    total_bytes += received;
    if (written * sizeof(uint8_t) != received) {
      printf ("Failed to write to the file the"
              " amount of data received from the network.\n");
      shutdown (accepted, SHUT_RDWR);
      shutdown (sock, SHUT_RDWR);
      close (accepted);
      close (sock);
      free (buffer);
      fclose (fp);
      return -EXIT_FAILURE;
    }
  }
  clock_gettime (CLOCK_MONOTONIC_RAW, &end_time);
  print_statistics (total_bytes, start_time, end_time);

  shutdown (accepted, SHUT_RDWR);
  shutdown (sock, SHUT_RDWR);
  close (accepted);
  close (sock);
  fclose (fp);
  free (buffer);

  return 0;
}

int 
server_microtcp(uint16_t listen_port, const char *file) {
    uint8_t *buffer;
    FILE *fp;
    ssize_t received;
    ssize_t written;
    ssize_t total_bytes = 0;
    struct timespec start_time, end_time;

    printf("Initializing microTCP server...\n");

    /* Initialize microTCP socket */
    microtcp_sock_t server_socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);
    if (server_socket.state == INVALID) {
        fprintf(stderr, "Failed to create microTCP socket\n");
        return -EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(listen_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    printf("Binding microTCP socket to port %d...\n", listen_port);
    if (microtcp_bind(&server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "microTCP bind failed\n");
        return -EXIT_FAILURE;
    }

    printf("Waiting for client connection...\n");
    if (microtcp_accept(&server_socket, NULL, 0) < 0) {
        fprintf(stderr, "microTCP accept failed\n");
        return -EXIT_FAILURE;
    }

    printf("Client connected successfully.\n");

    /* Allocate memory for the application receive buffer */
    buffer = (uint8_t *)malloc(CHUNK_SIZE);
    if (!buffer) {
        perror("Allocate application receive buffer");
        return -EXIT_FAILURE;
    }

    /* Open the file for writing the data from the network */
    fp = fopen(file, "w");
    if (!fp) {
        perror("Open file for writing");
        free(buffer);
        return -EXIT_FAILURE;
    }

    /* Start processing the received data */
    printf("Receiving data...\n");
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    while ((received = microtcp_recv(&server_socket, buffer, CHUNK_SIZE, 0)) > 0) {
        printf("Received %ld bytes\n", received);
        written = fwrite(buffer, sizeof(uint8_t), received, fp);
        total_bytes += received;
        if (written * sizeof(uint8_t) != received) {
            fprintf(stderr, "Failed to write received data to file\n");
            free(buffer);
            fclose(fp);
            return -EXIT_FAILURE;
        }
    }

    if (received == 0) {
      printf("FIN received. Closing connection.\n");
      printf("Socket state before shutdown: %d\n", server_socket.state);
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    print_statistics(total_bytes, start_time, end_time);

    printf("Reception completed. Total bytes received: %ld\n", total_bytes);

    free(buffer);
    fclose(fp);

    /* Shutdown the connection gracefully */
    printf("Shutting down the microTCP connection...\n");
    if (microtcp_shutdown(&server_socket, SHUT_RDWR) < 0) {
      fprintf(stderr, "Failed to shutdown microTCP connection. Socket state: %d\n", server_socket.state);
      return -EXIT_FAILURE;
    }

    printf("Connection terminated successfully.\n");
    return 0;
}    

int
client_tcp (const char *serverip, uint16_t server_port, const char *file)
{
  uint8_t *buffer;
  int sock;
  socklen_t client_addr_len;
  FILE *fp;
  size_t read_items = 0;
  ssize_t data_sent;

  struct sockaddr *client_addr;

  /* Allocate memory for the application receive buffer */
  buffer = (uint8_t *) malloc (CHUNK_SIZE);
  if (!buffer) {
    perror ("Allocate application receive buffer");
    return -EXIT_FAILURE;
  }

  /* Open the file for writing the data from the network */
  fp = fopen (file, "r");
  if (!fp) {
    perror ("Open file for reading");
    free (buffer);
    return -EXIT_FAILURE;
  }

  if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    perror ("Opening TCP socket");
    free (buffer);
    fclose (fp);
    return -EXIT_FAILURE;
  }

  struct sockaddr_in sin;
  memset (&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  /*Port that server listens at */
  sin.sin_port = htons (server_port);
  /* The server's IP*/
  sin.sin_addr.s_addr = inet_addr (serverip);

  if (connect (sock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in))
      == -1) {
    perror ("TCP connect");
    exit (EXIT_FAILURE);
  }

  printf ("Starting sending data...\n");
  /* Start sending the data */
  while (!feof (fp)) {
    read_items = fread (buffer, sizeof(uint8_t), CHUNK_SIZE, fp);
    if (read_items < 1) {
      perror ("Failed read from file");
      shutdown (sock, SHUT_RDWR);
      close (sock);
      free (buffer);
      fclose (fp);
      return -EXIT_FAILURE;
    }

    data_sent = send (sock, buffer, read_items * sizeof(uint8_t), 0);
    if (data_sent != read_items * sizeof(uint8_t)) {
      printf ("Failed to send the"
              " amount of data read from the file.\n");
      shutdown (sock, SHUT_RDWR);
      close (sock);
      free (buffer);
      fclose (fp);
      return -EXIT_FAILURE;
    }

  }

  printf ("Data sent. Terminating...\n");
  shutdown (sock, SHUT_RDWR);
  close (sock);
  free (buffer);
  fclose (fp);
  return 0;
}

int 
client_microtcp(const char *serverip, uint16_t server_port, const char *file) {
    uint8_t *buffer;
    FILE *fp;
    ssize_t read_items;
    ssize_t data_sent;

    printf("Initializing microTCP client...\n");

    /* Initialize microTCP socket */
    microtcp_sock_t client_socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);
    if (client_socket.state == INVALID) {
        fprintf(stderr, "Failed to create microTCP socket\n");
        return -EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, serverip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server IP address\n");
        return -EXIT_FAILURE;
    }

    printf("Connecting to server at %s:%d...\n", serverip, server_port);
    if (microtcp_connect(&client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "microTCP connect failed\n");
        return -EXIT_FAILURE;
    }

    /* Allocate memory for the application send buffer */
    buffer = (uint8_t *)malloc(CHUNK_SIZE);
    if (!buffer) {
        perror("Allocate application send buffer");
        return -EXIT_FAILURE;
    }

    printf("Opening file: %s\n", file);
    /* Open the file for reading the data to send */
    fp = fopen(file, "r");
    if (!fp) {
        perror("Open file for reading");
        free(buffer);
        return -EXIT_FAILURE;
    }

    printf("Starting to send data...\n");
    while (1) {
        /* Διαβάζουμε δεδομένα 1 byte τη φορά ώστε να πάρουμε ακριβώς τον αριθμό των bytes */
        read_items = fread(buffer, 1, CHUNK_SIZE, fp);
        if (read_items == 0)
            break;  /* EOF */

        printf("Read %ld bytes from file\n", read_items);

        data_sent = microtcp_send(&client_socket, buffer, read_items, 0);
        if (data_sent < 0) {
            fprintf(stderr, "Failed to send data\n");
            free(buffer);
            fclose(fp);
            return -EXIT_FAILURE;
        }
        printf("Sent %ld bytes to server\n", data_sent);
    }

    printf("Data sent. Terminating connection...\n");
    free(buffer);
    fclose(fp);
    microtcp_shutdown(&client_socket, SHUT_RDWR);
    return 0;
}

int
main (int argc, char **argv)
{
  int opt;
  int port;
  int exit_code = 0;
  char *filestr = NULL;
  char *ipstr = NULL;
  uint8_t is_server = 0;
  uint8_t use_microtcp = 0;

  /* A very easy way to parse command line arguments */
  while ((opt = getopt (argc, argv, "hsmf:p:a:")) != -1) {
    switch (opt)
      {
      /* If -s is set, program runs on server mode */
      case 's':
        is_server = 1;
        break;
        /* if -m is set the program should use the microTCP implementation */
      case 'm':
        use_microtcp = 1;
        break;
      case 'f':
        filestr = strdup (optarg);
        /* A few checks will be nice here...*/
        /* Convert the given file to absolute path */
        break;
      case 'p':
        port = atoi (optarg);
        /* To check or not to check? */
        break;
      case 'a':
        ipstr = strdup (optarg);
        break;

      default:
        printf (
            "Usage: bandwidth_test [-s] [-m] -p port -f file"
            "Options:\n"
            "   -s                  If set, the program runs as server. Otherwise as client.\n"
            "   -m                  If set, the program uses the microTCP implementation. Otherwise the normal TCP.\n"
            "   -f <string>         If -s is set the -f option specifies the filename of the file that will be saved.\n"
            "                       If not, is the source file at the client side that will be sent to the server.\n"
            "   -p <int>            The listening port of the server\n"
            "   -a <string>         The IP address of the server. This option is ignored if the tool runs in server mode.\n"
            "   -h                  prints this help\n");
        exit (EXIT_FAILURE);
      }
  }

  /*
   * TODO: Some error checking here???
   */

  /*
   * Depending the use arguments execute the appropriate functions
   */
  if (is_server) {

    if (use_microtcp) {
      exit_code = server_microtcp (port, filestr);
    }
    else {
      exit_code = server_tcp (port, filestr);
    }
  }
  else {
    if (use_microtcp) {
      exit_code = client_microtcp (ipstr, port, filestr);
    }
    else {
      exit_code = client_tcp (ipstr, port, filestr);
    }
  }

  free (filestr);
  free (ipstr);
  return exit_code;
}

