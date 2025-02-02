/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * See microtcp.h for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "microtcp.h"
#include "../utils/crc32.h"

/* -------------------- microtcp_socket -------------------- */
microtcp_sock_t microtcp_socket(int domain, int type, int protocol)
{
  microtcp_sock_t sock;

  // Create the underlying UDP socket
  sock.sd = socket(domain, type, protocol);
  if (sock.sd < 0)
  {
    perror("Failed to create UDP socket");
    sock.state = INVALID;
    return sock;
  }

  // Initialize state variables
  sock.state = CLOSED; // Default state
  sock.init_win_size = MICROTCP_WIN_SIZE;
  sock.curr_win_size = MICROTCP_WIN_SIZE;

  // Allocate memory for the receive buffer
  sock.recvbuf = (uint8_t *)malloc(MICROTCP_RECVBUF_LEN);
  if (!sock.recvbuf)
  {
    perror("Failed to allocate memory for receive buffer");
    close(sock.sd);
    sock.state = INVALID;
    return sock;
  }
  sock.buf_fill_level = 0;

  // Congestion control variables
  sock.cwnd = MICROTCP_INIT_CWND;
  sock.ssthresh = MICROTCP_INIT_SSTHRESH;

  sock.seq_number = 0;
  sock.ack_number = 0;

  // Initialize additional fields for sequence and retransmission handling
  sock.expected_seq = 0;
  sock.last_acked_seq = 0;
  sock.dup_ack_count = 0;
  sock.last_sent_segment = NULL;
  sock.last_sent_length = 0;

  // Statistics
  sock.packets_send = 0;
  sock.packets_received = 0;
  sock.packets_lost = 0;
  sock.bytes_send = 0;
  sock.bytes_received = 0;
  sock.bytes_lost = 0;

  printf("Socket created with state: %d\n", sock.state);
  return sock;
}

/* -------------------- microtcp_bind -------------------- */
int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  if (!socket || socket->state == INVALID)
  {
    fprintf(stderr, "Invalid microTCP socket\n");
    return -1;
  }

  if (bind(socket->sd, address, address_len) < 0)
  {
    perror("bind");
    return -1;
  }

  socket->state = LISTEN;
  return 0;
}

/* -------------------- microtcp_connect -------------------- */
int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len)
{
  printf("microtcp_connect: Starting connection process...\n");

  if (!socket || socket->state == INVALID)
  {
    fprintf(stderr, "microtcp_connect: Invalid microTCP socket\n");
    return -1;
  }

  printf("microtcp_connect: Initial socket state: %d\n", socket->state);

  // Prepare and send a SYN packet
  microtcp_header_t syn_packet;
  memset(&syn_packet, 0, sizeof(syn_packet));

  srand(time(NULL));
  syn_packet.control = 0x02; // SYN flag
  syn_packet.seq_number = rand() % UINT32_MAX;
  syn_packet.window = htons(MICROTCP_WIN_SIZE);
  syn_packet.checksum = 0;
  syn_packet.checksum = htonl(crc32((uint8_t *)&syn_packet, sizeof(syn_packet)));

  printf("microtcp_connect: SYN Packet -> seq_number: %u, checksum: %u\n",
         syn_packet.seq_number, ntohl(syn_packet.checksum));

  if (sendto(socket->sd, &syn_packet, sizeof(syn_packet), 0, address, address_len) < 0)
  {
    perror("microtcp_connect: Failed to send SYN packet");
    return -1;
  }
  printf("SYN Packet Sent (Raw Data):\n");
  for (size_t i = 0; i < sizeof(syn_packet); i++)
  {
    printf("%02X ", ((uint8_t *)&syn_packet)[i]);
  }
  printf("\n");

  // Wait for SYN-ACK response
  microtcp_header_t syn_ack_packet;
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_len = sizeof(recv_addr);
  if (recvfrom(socket->sd, &syn_ack_packet, sizeof(syn_ack_packet), 0,
               (struct sockaddr *)&recv_addr, &recv_addr_len) < 0)
  {
    perror("microtcp_connect: Failed to receive SYN-ACK packet");
    return -1;
  }

  printf("microtcp_connect: Received SYN-ACK -> seq_number: %u, ack_number: %u, checksum: %u\n",
         syn_ack_packet.seq_number, syn_ack_packet.ack_number, ntohl(syn_ack_packet.checksum));

  uint32_t received_checksum = ntohl(syn_ack_packet.checksum);
  syn_ack_packet.checksum = 0;
  uint32_t calculated_checksum = crc32((uint8_t *)&syn_ack_packet, sizeof(syn_ack_packet));

  if (calculated_checksum != received_checksum)
  {
    fprintf(stderr, "microtcp_connect: Checksum validation failed\n");
    return -1;
  }

  if (!(syn_ack_packet.control & 0x12))
  {
    fprintf(stderr, "microtcp_connect: Unexpected packet type\n");
    return -1;
  }

  printf("microtcp_connect: SYN-ACK received successfully\n");

  // Send final ACK packet
  socket->ack_number = ntohl(syn_ack_packet.seq_number) + 1;
  socket->seq_number = ntohl(syn_ack_packet.ack_number);

  microtcp_header_t ack_packet;
  memset(&ack_packet, 0, sizeof(ack_packet));
  ack_packet.control = 0x10; // ACK flag
  ack_packet.seq_number = htonl(socket->seq_number);
  ack_packet.ack_number = htonl(socket->ack_number);
  ack_packet.window = htons(MICROTCP_WIN_SIZE);
  ack_packet.checksum = 0;
  ack_packet.checksum = htonl(crc32((uint8_t *)&ack_packet, sizeof(ack_packet)));

  printf("microtcp_connect: Sending final ACK packet...\n");
  if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, address, address_len) < 0)
  {
    perror("microtcp_connect: Failed to send ACK packet");
    return -1;
  }

  printf("microtcp_connect: Connection established\n");

  // Connect underlying socket to peer address for subsequent communications
  if (connect(socket->sd, address, address_len) < 0)
  {
    perror("microtcp_connect: Failed to bind socket to destination address");
    return -1;
  }

  socket->state = ESTABLISHED;
  // Initialize expected sequence number for incoming data:
  socket->expected_seq = 0;
  socket->last_acked_seq = 0;
  socket->dup_ack_count = 0;
  return 0;
}

/* -------------------- microtcp_accept -------------------- */
int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
    printf("microtcp_accept: Waiting for connection...\n");
    if (!socket || socket->state != LISTEN) {
        fprintf(stderr, "microtcp_accept: Socket not in LISTEN state\n");
        return -1;
    }

    uint8_t buffer[MICROTCP_MSS + sizeof(microtcp_header_t)];
    microtcp_header_t *header = (microtcp_header_t *)buffer;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        printf("microtcp_accept: Waiting for SYN packet...\n");
        memset(buffer, 0, sizeof(buffer));
        ssize_t received_len = recvfrom(socket->sd, buffer, sizeof(buffer), 0,
                                        (struct sockaddr *)&client_addr, &client_addr_len);
        if (received_len < (ssize_t)sizeof(microtcp_header_t)) {
            printf("microtcp_accept: Ignored invalid packet\n");
            continue;
        }

        uint32_t received_checksum = ntohl(header->checksum);
        header->checksum = 0;
        uint32_t calculated_checksum = crc32(buffer, sizeof(microtcp_header_t));
        if (calculated_checksum != received_checksum) {
            fprintf(stderr, "microtcp_accept: Checksum validation failed\n");
            continue;
        }

        if (header->control & 0x02) { // SYN flag
            printf("microtcp_accept: SYN packet received successfully\n");
            socket->seq_number = rand();
            socket->ack_number = ntohl(header->seq_number) + 1;

            microtcp_header_t syn_ack = {0};
            syn_ack.seq_number = htonl(socket->seq_number);
            syn_ack.ack_number = htonl(socket->ack_number);
            syn_ack.control = 0x12; // SYN and ACK flags
            syn_ack.window = htons(MICROTCP_WIN_SIZE);
            syn_ack.checksum = 0;
            syn_ack.checksum = htonl(crc32((uint8_t *)&syn_ack, sizeof(syn_ack)));

            printf("microtcp_accept: Sending SYN-ACK...\n");
            if (sendto(socket->sd, &syn_ack, sizeof(syn_ack), 0, 
                       (struct sockaddr *)&client_addr, client_addr_len) < 0) {
                perror("microtcp_accept: Failed to send SYN-ACK");
                return -1;
            }

            printf("microtcp_accept: Waiting for final ACK...\n");
            memset(buffer, 0, sizeof(buffer));
            received_len = recvfrom(socket->sd, buffer, sizeof(buffer), 0, NULL, NULL);
            if (received_len < (ssize_t)sizeof(microtcp_header_t)) {
                fprintf(stderr, "microtcp_accept: Invalid final ACK packet\n");
                return -1;
            }

            received_checksum = ntohl(header->checksum);
            header->checksum = 0;
            calculated_checksum = crc32(buffer, sizeof(microtcp_header_t));
            if (calculated_checksum != received_checksum || !(header->control & 0x10)) {
                fprintf(stderr, "microtcp_accept: Final ACK validation failed\n");
                return -1;
            }

            printf("microtcp_accept: Connection established\n");

            if (connect(socket->sd, (struct sockaddr *)&client_addr, client_addr_len) < 0) {
                perror("microtcp_accept: Failed to bind socket to client address");
                return -1;
            }

            socket->state = ESTABLISHED;
            // **Τροποποίηση:** Αντί να θέτουμε expected_seq = 0, παίρνουμε το seq number από το final ACK.
            microtcp_header_t *final_ack = (microtcp_header_t *) buffer;
            socket->expected_seq = ntohl(final_ack->seq_number);
            socket->last_acked_seq = socket->expected_seq;
            socket->dup_ack_count = 0;
            return 0;
        }
    }
}

/* -------------------- microtcp_shutdown -------------------- */
int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  if (!socket || (socket->state != ESTABLISHED && socket->state != CLOSING_BY_PEER))
  {
    fprintf(stderr, "Socket not in a valid state for shutdown. Current state: %d\n", socket->state);
    return -1;
  }

  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);

  /* Δήλωση μεταβλητών για το checksum */
  uint32_t received_checksum, calculated_checksum;

  if (getpeername(socket->sd, (struct sockaddr *)&peer_addr, &peer_addr_len) < 0)
  {
    perror("Failed to get peer address");
    return -1;
  }

  printf("Shutting down connection. Current state: %d\n", socket->state);

  if (socket->state == ESTABLISHED)
  {
    // CLIENT LOGIC
    microtcp_header_t fin_packet = {0};
    fin_packet.control = 0x01; // FIN flag
    fin_packet.seq_number = htonl(socket->seq_number++);
    fin_packet.ack_number = htonl(socket->ack_number);
    fin_packet.checksum = 0;
    fin_packet.checksum = htonl(crc32((uint8_t *)&fin_packet, sizeof(fin_packet)));

    printf("Sending FIN packet: seq_number=%u, ack_number=%u\n",
           ntohl(fin_packet.seq_number), ntohl(fin_packet.ack_number));
    if (sendto(socket->sd, &fin_packet, sizeof(fin_packet), 0,
               (struct sockaddr *)&peer_addr, peer_addr_len) < 0)
    {
      perror("Failed to send FIN packet");
      return -1;
    }

    microtcp_header_t ack_packet;
    if (recvfrom(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, NULL) < 0)
    {
      perror("Failed to receive ACK packet");
      return -1;
    }
    received_checksum = ntohl(ack_packet.checksum);
    ack_packet.checksum = 0;
    calculated_checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

    printf("Received ACK: checksum=%u, calculated_checksum=%u\n",
           received_checksum, calculated_checksum);

    if (calculated_checksum != received_checksum || !(ack_packet.control & 0x10))
    {
      fprintf(stderr, "Invalid ACK packet received\n");
      return -1;
    }

    microtcp_header_t server_fin_packet;
    if (recvfrom(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0, NULL, NULL) < 0)
    {
      perror("Failed to receive FIN packet from server");
      return -1;
    }
    received_checksum = ntohl(server_fin_packet.checksum);
    server_fin_packet.checksum = 0;
    calculated_checksum = crc32((uint8_t *)&server_fin_packet, sizeof(server_fin_packet));

    printf("Received FIN: checksum=%u, calculated_checksum=%u\n",
           received_checksum, calculated_checksum);

    if (calculated_checksum != received_checksum ||
        (!(server_fin_packet.control & 0x01) && !(server_fin_packet.control & 0x11)))
    {
      fprintf(stderr, "Invalid FIN packet received\n");
      return -1;
    }

    microtcp_header_t client_ack_packet = {0};
    client_ack_packet.control = 0x10; // ACK flag
    client_ack_packet.seq_number = htonl(socket->seq_number++);
    client_ack_packet.ack_number = htonl(ntohl(server_fin_packet.seq_number) + 1);
    client_ack_packet.checksum = 0;
    client_ack_packet.checksum = htonl(crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet)));

    printf("Sending ACK for FIN: seq_number=%u, ack_number=%u\n",
           ntohl(client_ack_packet.seq_number), ntohl(client_ack_packet.ack_number));
    if (sendto(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0,
               (struct sockaddr *)&peer_addr, peer_addr_len) < 0)
    {
      perror("Failed to send ACK for FIN");
      return -1;
    }

    socket->state = CLOSED;
    printf("Connection successfully closed by client\n");
    return 0;
  }

  if (socket->state == CLOSING_BY_PEER)
  {
    // SERVER LOGIC
    printf("Server received FIN. Sending ACK...\n");
    microtcp_header_t ack_packet = {0};
    ack_packet.control = 0x10; // ACK flag
    ack_packet.seq_number = htonl(socket->seq_number++);
    ack_packet.ack_number = htonl(socket->ack_number);
    ack_packet.checksum = 0;
    ack_packet.checksum = htonl(crc32((uint8_t *)&ack_packet, sizeof(ack_packet)));

    if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0,
               (struct sockaddr *)&peer_addr, peer_addr_len) < 0)
    {
      perror("Failed to send ACK for FIN");
      return -1;
    }

    printf("Server sending its own FIN...\n");
    microtcp_header_t server_fin_packet = {0};
    server_fin_packet.control = 0x01; // FIN flag
    server_fin_packet.seq_number = htonl(socket->seq_number++);
    server_fin_packet.ack_number = htonl(socket->ack_number);
    server_fin_packet.checksum = 0;
    server_fin_packet.checksum = htonl(crc32((uint8_t *)&server_fin_packet, sizeof(server_fin_packet)));

    if (sendto(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0,
               (struct sockaddr *)&peer_addr, peer_addr_len) < 0)
    {
      perror("Failed to send FIN packet");
      return -1;
    }

    microtcp_header_t client_ack_packet;
    if (recvfrom(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, NULL, NULL) < 0)
    {
      perror("Failed to receive final ACK from client");
      return -1;
    }
    received_checksum = ntohl(client_ack_packet.checksum);
    client_ack_packet.checksum = 0;
    calculated_checksum = crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet));
    if (calculated_checksum != received_checksum || !(client_ack_packet.control & 0x10))
    {
      fprintf(stderr, "Invalid final ACK received\n");
      return -1;
    }
    socket->state = CLOSED;
    printf("Connection successfully closed by server\n");
    return 0;
  }

  return -1;
}

/* -------------------- microtcp_send -------------------- */
/* -------------------- microtcp_send -------------------- */
ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  if (!socket || (socket->state != ESTABLISHED && socket->state != CLOSED && socket->state != LISTEN))
  {
    fprintf(stderr, "microtcp_send: Socket not in a valid state\n");
    return -1;
  }

  if (!buffer || length == 0)
  {
    fprintf(stderr, "microtcp_send: Invalid buffer or length\n");
    return -1;
  }

  size_t bytes_sent = 0;

  while (bytes_sent < length)
  {
    /* Υπολογισμός effective window = min(cwnd, curr_win_size) */
    size_t effective_window = (socket->cwnd < socket->curr_win_size) ? socket->cwnd : socket->curr_win_size;

    /* Αν το effective window είναι 0, στέλνουμε probe πακέτο μέχρι να έχουμε διαθέσιμο χώρο */
    if (effective_window == 0) {
      unsigned int wait_time = rand() % MICROTCP_ACK_TIMEOUT_US;
      usleep(wait_time);
      /* Probe packet χωρίς payload (data_len = 0) */
      microtcp_header_t probe_packet = {0};
      probe_packet.control = 0x00; // Data flag
      probe_packet.seq_number = htonl(socket->seq_number);
      probe_packet.ack_number = htonl(socket->ack_number);
      probe_packet.data_len = htonl(0);
      probe_packet.checksum = 0;
      probe_packet.checksum = htonl(crc32((uint8_t *)&probe_packet, sizeof(probe_packet)));
      if (sendto(socket->sd, &probe_packet, sizeof(probe_packet), flags, NULL, 0) < 0) {
        perror("microtcp_send: Failed to send probe packet");
        return -1;
      }
      /* Προσπαθούμε να λάβουμε ACK για να ενημερωθεί το curr_win_size */
      microtcp_header_t ack_probe;
      ssize_t ack_received = recvfrom(socket->sd, &ack_probe, sizeof(ack_probe), 0, NULL, NULL);
      if (ack_received >= 0) {
        uint16_t remote_win = ntohs(ack_probe.window);
        socket->curr_win_size = remote_win;
      }
      continue; /* Επαναλαμβάνουμε για να επανυπολογίσουμε το effective_window */
    }

    /* Εάν το segment_size που θέλουμε να στείλουμε υπερβαίνει το effective window, το μειώνουμε */
    size_t segment_size = (length - bytes_sent > MICROTCP_MSS) ? MICROTCP_MSS : length - bytes_sent;
    if (segment_size > effective_window) {
      segment_size = effective_window;
    }

    /* Δημιουργία του data packet */
    microtcp_header_t data_packet = {0};
    data_packet.control = 0x00; // Data flag
    data_packet.seq_number = htonl(socket->seq_number);
    data_packet.ack_number = htonl(socket->ack_number);
    data_packet.data_len = htonl(segment_size);

    uint8_t sendbuf[MICROTCP_MSS + sizeof(microtcp_header_t)];
    memcpy(sendbuf, &data_packet, sizeof(data_packet));
    memcpy(sendbuf + sizeof(data_packet), (uint8_t *)buffer + bytes_sent, segment_size);
    data_packet.checksum = 0;
    data_packet.checksum = htonl(crc32(sendbuf, sizeof(data_packet) + segment_size));
    memcpy(sendbuf, &data_packet, sizeof(data_packet));

    /* Αποθήκευση του τελευταίου σταλθέντος πακέτου για retransmission */
    if (socket->last_sent_segment)
      free(socket->last_sent_segment);
    socket->last_sent_segment = malloc(sizeof(sendbuf));
    memcpy(socket->last_sent_segment, sendbuf, sizeof(data_packet) + segment_size);
    socket->last_sent_length = sizeof(data_packet) + segment_size;

    /* Αποστολή του πακέτου */
    if (sendto(socket->sd, sendbuf, sizeof(data_packet) + segment_size, flags, NULL, 0) < 0) {
      perror("microtcp_send: Failed to send data packet");
      return -1;
    }
    socket->packets_send++;
    socket->bytes_send += segment_size;
    printf("Sent %zu bytes, seq_number: %zu\n", segment_size, socket->seq_number);

    /* Ρύθμιση timeout για λήψη ACK */
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
      perror("setsockopt");
    }

    /* Αναμονή για ACK */
    microtcp_header_t ack_packet;
    ssize_t ack_received = recvfrom(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, NULL);
    if (ack_received < 0) {
      printf("Timeout occurred, retransmitting\n");
      sendto(socket->sd, socket->last_sent_segment, socket->last_sent_length, flags, NULL, 0);
      socket->ssthresh = socket->cwnd / 2;
      socket->cwnd = (MICROTCP_MSS < socket->ssthresh) ? MICROTCP_MSS : socket->ssthresh;
      continue;
    } else {
      /* Ενημέρωση του receiver window από το πεδίο window του ACK */
      uint16_t remote_win = ntohs(ack_packet.window);
      socket->curr_win_size = remote_win;

      uint32_t received_ack = ntohl(ack_packet.ack_number);
      uint32_t ack_recv_checksum = ntohl(ack_packet.checksum);
      ack_packet.checksum = 0;
      uint32_t calc_ack_checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));
      if (calc_ack_checksum != ack_recv_checksum || !(ack_packet.control & 0x10)) {
        fprintf(stderr, "Invalid ACK received\n");
        continue;
      }

      /* Έλεγχος για duplicate ACK */
      if (received_ack == socket->last_acked_seq) {
        socket->dup_ack_count++;
        printf("Duplicate ACK received: %u (count=%d)\n", received_ack, socket->dup_ack_count);
        if (socket->dup_ack_count == 3) {
          printf("Fast retransmit triggered, resending last packet\n");
          sendto(socket->sd, socket->last_sent_segment, socket->last_sent_length, flags, NULL, 0);
          socket->ssthresh = socket->cwnd / 2;
          socket->cwnd = socket->ssthresh + 1;
          socket->dup_ack_count = 0;
          continue;
        }
      } else if (received_ack > socket->last_acked_seq) {
        socket->dup_ack_count = 0;
        socket->last_acked_seq = received_ack;
        /* Ενημέρωση του congestion window */
        if (socket->cwnd <= socket->ssthresh) {
          socket->cwnd += MICROTCP_MSS;
        } else {
          socket->cwnd += (MICROTCP_MSS * MICROTCP_MSS) / socket->cwnd;
        }
        socket->seq_number += segment_size;
        bytes_sent += segment_size;
      }
    }
  }
  return bytes_sent;
}

/* -------------------- microtcp_recv -------------------- */
ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  if (!socket || (socket->state != ESTABLISHED && socket->state != LISTEN && socket->state != CLOSED))
  {
    fprintf(stderr, "microtcp_recv: Socket not in a valid state for receiving packets\n");
    return -1;
  }
  if (!buffer || length == 0)
  {
    fprintf(stderr, "microtcp_recv: Invalid buffer or length\n");
    return -1;
  }

  uint8_t recvbuf[MICROTCP_MSS + sizeof(microtcp_header_t)];
  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  ssize_t received = recvfrom(socket->sd, recvbuf, sizeof(recvbuf), flags,
                              (struct sockaddr *)&peer_addr, &peer_addr_len);
  if (received < (ssize_t)sizeof(microtcp_header_t))
  {
    fprintf(stderr, "microtcp_recv: Received invalid packet\n");
    return -1;
  }

  microtcp_header_t *header = (microtcp_header_t *)recvbuf;
  uint32_t received_checksum = ntohl(header->checksum);
  header->checksum = 0;
  if (crc32(recvbuf, received) != received_checksum)
  {
    fprintf(stderr, "microtcp_recv: Checksum validation failed\n");
    return -1;
  }

  /* Έλεγχος αν το πακέτο είναι FIN */
  if (header->control & 0x01)
  {
    printf("microtcp_recv: FIN packet received\n");
    socket->state = CLOSING_BY_PEER;
    return 0;
  }

  /* Έλεγχος σωστής σειράς */
  uint32_t received_seq = ntohl(header->seq_number);
  if (received_seq != socket->expected_seq)
  {
    printf("microtcp_recv: Out-of-order packet received (expected: %u, got: %u)\n",
           socket->expected_seq, received_seq);
    /* Αποστολή duplicate ACK για το τελευταίο σωστό byte */
    microtcp_header_t dup_ack = {0};
    dup_ack.control = 0x10; // ACK flag
    dup_ack.ack_number = htonl(socket->expected_seq);
    dup_ack.window = htons(MICROTCP_RECVBUF_LEN - socket->buf_fill_level);
    dup_ack.checksum = 0;
    dup_ack.checksum = htonl(crc32((uint8_t *)&dup_ack, sizeof(dup_ack)));
    sendto(socket->sd, &dup_ack, sizeof(dup_ack), 0, (struct sockaddr *)&peer_addr, peer_addr_len);
    return -1;
  }

  size_t data_length = received - sizeof(microtcp_header_t);
  if (data_length > length)
  {
    fprintf(stderr, "microtcp_recv: Buffer too small for received data\n");
    return -1;
  }
  memcpy(buffer, recvbuf + sizeof(microtcp_header_t), data_length);

  socket->expected_seq += data_length;
  socket->bytes_received += data_length;
  socket->packets_received++;

  /* Αποστολή κανονικού ACK */
  microtcp_header_t ack_packet = {0};
  ack_packet.control = 0x10; // ACK flag
  ack_packet.ack_number = htonl(socket->expected_seq);
  ack_packet.window = htons(MICROTCP_RECVBUF_LEN - socket->buf_fill_level);
  ack_packet.checksum = 0;
  ack_packet.checksum = htonl(crc32((uint8_t *)&ack_packet, sizeof(ack_packet)));
  sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&peer_addr, peer_addr_len);
  printf("microtcp_recv: ACK sent, ack_number: %u\n", socket->expected_seq);

  return data_length;
}
