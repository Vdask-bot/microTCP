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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include "microtcp.h"
#include "../utils/crc32.h"

microtcp_sock_t
microtcp_socket(int domain, int type, int protocol)
{
  microtcp_sock_t sock;

  // Create the UDP socket
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
    close(sock.sd); // Clean up socket if buffer allocation fails
    sock.state = INVALID;
    return sock;
  }

  sock.buf_fill_level = 0;

  // Congestion control variables
  sock.cwnd = MICROTCP_INIT_CWND;
  sock.ssthresh = MICROTCP_INIT_SSTHRESH;

  sock.seq_number = 0;
  sock.ack_number = 0;

  // Initialize statistics
  sock.packets_send = 0;
  sock.packets_received = 0;
  sock.packets_lost = 0;
  sock.bytes_send = 0;
  sock.bytes_received = 0;
  sock.bytes_lost = 0;

  return sock;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  if (!socket || socket->state == INVALID)
  {
    fprintf(stderr, "Invalid microTCP socket\n");
    return -1;
  }

  // Attempt to bind the underlying UDP socket
  if (bind(socket->sd, address, address_len) < 0)
  {
    perror("bind");
    return -1;
  }

  // If binding is successful, update the state if necessary
  socket->state = LISTEN;
  return 0;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len)
{
  if (!socket || socket->state == INVALID)
  {
    fprintf(stderr, "Invalid microTCP socket\n");
    return -1;
  }

  // Step 1: Prepare and send a packet to initiate the connection
  microtcp_header_t syn_packet;
  memset(&syn_packet, 0, sizeof(syn_packet));

  srand(time(NULL));                           // Ensure random initialization for the sequence number
  syn_packet.control = 0x02;                   // SYN flag
  syn_packet.seq_number = rand() % UINT32_MAX; // Random sequence number
  syn_packet.window = MICROTCP_WIN_SIZE;       // Set initial flow control window size
  syn_packet.checksum = 0;
  syn_packet.checksum = crc32((uint8_t *)&syn_packet, sizeof(syn_packet)); // Calculate checksum

  if (sendto(socket->sd, &syn_packet, sizeof(syn_packet), 0, address, address_len) < 0)
  {
    perror("Failed to send packet");
    return -1;
  }

  // Step 2: Wait for a response from the other side
  microtcp_header_t syn_ack_packet;
  socklen_t addr_len = address_len;
  if (recvfrom(socket->sd, &syn_ack_packet, sizeof(syn_ack_packet), 0, (struct sockaddr *)address, &addr_len) < 0)
  {
    perror("Failed to receive response packet");
    return -1;
  }

  // Validate the received packet
  uint32_t received_checksum = syn_ack_packet.checksum;
  syn_ack_packet.checksum = 0; // Reset checksum for validation
  if (crc32((uint8_t *)&syn_ack_packet, sizeof(syn_ack_packet)) != received_checksum)
  {
    fprintf(stderr, "Checksum validation failed\n");
    return -1;
  }

  // Check flags in the response packet
  if (!(syn_ack_packet.control & 0x02) || !(syn_ack_packet.control & 0x10))
  { // SYN and ACK must be set
    fprintf(stderr, "Unexpected packet type\n");
    return -1;
  }

  // Step 3: Update connection parameters
  socket->ack_number = syn_ack_packet.seq_number + 1;
  socket->seq_number = syn_ack_packet.ack_number;
  socket->init_win_size = syn_ack_packet.window; // Store the initial flow control window size

  // Step 4: Send the final acknowledgment to confirm the connection
  microtcp_header_t ack_packet;
  memset(&ack_packet, 0, sizeof(ack_packet));

  ack_packet.control = 0x10; // ACK flag
  ack_packet.seq_number = socket->seq_number;
  ack_packet.ack_number = socket->ack_number;
  ack_packet.window = MICROTCP_WIN_SIZE;       // Send own flow control window size
  ack_packet.checksum = 0;
  ack_packet.checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

  if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, address, address_len) < 0)
  {
    perror("Failed to send acknowledgment");
    return -1;
  }

  // Finalize connection setup
  socket->state = ESTABLISHED;
  return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len)
{
  if (!socket || socket->state != LISTEN)
  {
    fprintf(stderr, "Socket not in LISTEN state\n");
    return -1;
  }

  uint8_t buffer[MICROTCP_MSS + sizeof(microtcp_header_t)];
  microtcp_header_t *header = (microtcp_header_t *)buffer;

  // Wait for a SYN packet
  while (1)
  {
    ssize_t received_len = recvfrom(socket->sd, buffer, sizeof(buffer), 0, address, &address_len);
    if (received_len < sizeof(microtcp_header_t))
    {
      continue; // Ignore invalid packets
    }

    // Verify SYN and checksum
    if ((header->control & (1 << 14)) && crc32(buffer, received_len) == header->checksum)
    {
      // Respond with SYN-ACK
      socket->seq_number = rand();
      socket->ack_number = header->seq_number + 1;
      socket->init_win_size = header->window; // Store the received initial window size

      microtcp_header_t syn_ack = {
          .seq_number = socket->seq_number,
          .ack_number = socket->ack_number,
          .control = (1 << 15) | (1 << 14), // SYN and ACK
          .window = MICROTCP_WIN_SIZE,     // Send own flow control window size
          .checksum = 0};
      syn_ack.checksum = crc32((uint8_t *)&syn_ack, sizeof(syn_ack));

      if (sendto(socket->sd, &syn_ack, sizeof(syn_ack), 0, address, address_len) < 0)
      {
        return -1;
      }
      break; // SYN-ACK sent, exit loop
    }
  }

  // Wait for ACK
  while (1)
  {
    ssize_t received_len = recvfrom(socket->sd, buffer, sizeof(buffer), 0, address, &address_len);
    if (received_len < sizeof(microtcp_header_t))
    {
      continue; // Ignore invalid packets
    }

    // Verify ACK and checksum
    if ((header->control & (1 << 15)) && crc32(buffer, received_len) == header->checksum)
    {
      if (header->ack_number == socket->seq_number + 1)
      {
        socket->state = ESTABLISHED; // Connection established
        socket->curr_win_size = header->window; // Store the current window size from ACK
        return 0;
      }
    }
  }

  return -1; // If handshake fails
}


int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    if (!socket || (socket->state != ESTABLISHED && socket->state != CLOSING_BY_PEER)) {
        fprintf(stderr, "Socket not in a valid state for shutdown\n");
        return -1;
    }

    if (socket->state == ESTABLISHED) {
        // CLIENT LOGIC
        // Step 1: Client sends FIN packet
        microtcp_header_t fin_packet;
        memset(&fin_packet, 0, sizeof(fin_packet));

        fin_packet.control = 0x01; // FIN flag
        fin_packet.seq_number = socket->seq_number++;
        fin_packet.ack_number = socket->ack_number;
        fin_packet.checksum = 0;
        fin_packet.checksum = crc32((uint8_t *)&fin_packet, sizeof(fin_packet));

        if (sendto(socket->sd, &fin_packet, sizeof(fin_packet), 0, NULL, 0) < 0) {
            perror("Failed to send FIN packet");
            return -1;
        }

        printf("FIN packet sent, seq_number: %u\n", fin_packet.seq_number);

        // Step 2: Client waits for ACK from server
        microtcp_header_t ack_packet;
        if (recvfrom(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, NULL) < 0) {
            perror("Failed to receive ACK packet");
            return -1;
        }

        uint32_t received_checksum = ack_packet.checksum;
        ack_packet.checksum = 0; // Reset checksum for validation
        if (crc32((uint8_t *)&ack_packet, sizeof(ack_packet)) != received_checksum ||
            !(ack_packet.control & 0x10)) {
            fprintf(stderr, "Invalid ACK packet received\n");
            return -1;
        }

        printf("ACK received, ack_number: %u\n", ack_packet.ack_number);
        socket->state = CLOSING_BY_HOST;

        // Step 3: Client waits for FIN packet from server
        microtcp_header_t server_fin_packet;
        if (recvfrom(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0, NULL, NULL) < 0) {
            perror("Failed to receive FIN packet from server");
            return -1;
        }

        received_checksum = server_fin_packet.checksum;
        server_fin_packet.checksum = 0; // Reset checksum for validation
        if (crc32((uint8_t *)&server_fin_packet, sizeof(server_fin_packet)) != received_checksum ||
            !(server_fin_packet.control & 0x01)) {
            fprintf(stderr, "Invalid FIN packet received from server\n");
            return -1;
        }

        printf("FIN received from server, seq_number: %u\n", server_fin_packet.seq_number);

        // Step 4: Client sends ACK to server's FIN
        microtcp_header_t client_ack_packet;
        memset(&client_ack_packet, 0, sizeof(client_ack_packet));

        client_ack_packet.control = 0x10; // ACK flag
        client_ack_packet.seq_number = socket->seq_number++;
        client_ack_packet.ack_number = server_fin_packet.seq_number + 1;
        client_ack_packet.checksum = 0;
        client_ack_packet.checksum = crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet));

        if (sendto(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, NULL, 0) < 0) {
            perror("Failed to send ACK for server FIN");
            return -1;
        }

        printf("ACK sent to server's FIN, ack_number: %u\n", client_ack_packet.ack_number);

        // Finalize the connection state
        socket->state = CLOSED;
        printf("Connection closed by client\n");

        return 0;
    }

    if (socket->state == CLOSING_BY_PEER) {
        // SERVER LOGIC
        // Step 1: Server sends ACK for client's FIN
        microtcp_header_t ack_packet;
        memset(&ack_packet, 0, sizeof(ack_packet));

        ack_packet.control = 0x10; // ACK flag
        ack_packet.seq_number = socket->seq_number;
        ack_packet.ack_number = socket->ack_number + 1;
        ack_packet.checksum = 0;
        ack_packet.checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

        if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, 0) < 0) {
            perror("Failed to send ACK for client's FIN");
            return -1;
        }

        printf("ACK sent for client's FIN\n");

        // Step 2: Server sends its own FIN
        microtcp_header_t fin_packet;
        memset(&fin_packet, 0, sizeof(fin_packet));

        fin_packet.control = 0x01; // FIN flag
        fin_packet.seq_number = socket->seq_number++;
        fin_packet.ack_number = socket->ack_number;
        fin_packet.checksum = 0;
        fin_packet.checksum = crc32((uint8_t *)&fin_packet, sizeof(fin_packet));

        if (sendto(socket->sd, &fin_packet, sizeof(fin_packet), 0, NULL, 0) < 0) {
            perror("Failed to send FIN");
            return -1;
        }

        printf("Server FIN sent\n");

        // Step 3: Server waits for ACK from client
        microtcp_header_t client_ack_packet;
        if (recvfrom(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, NULL, NULL) < 0) {
            perror("Failed to receive ACK for server FIN");
            return -1;
        }

        uint32_t received_checksum = client_ack_packet.checksum;
        client_ack_packet.checksum = 0; // Reset checksum for validation
        if (crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet)) != received_checksum ||
            !(client_ack_packet.control & 0x10)) {
            fprintf(stderr, "Invalid ACK for server FIN\n");
            return -1;
        }

        printf("ACK received for server FIN\n");

        // Finalize the connection state
        socket->state = CLOSED;
        printf("Connection closed by server\n");

        return 0;
    }

    return -1;
}

ssize_t 
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    if (!socket || socket->state != ESTABLISHED) {
        fprintf(stderr, "Socket not in ESTABLISHED state\n");
        return -1;
    }

    if (!buffer || length == 0) {
        fprintf(stderr, "Invalid buffer or length\n");
        return -1;
    }

    size_t bytes_sent = 0;
    size_t duplicate_ack_count = 0;
    size_t cwnd = socket->cwnd;
    size_t ssthresh = socket->ssthresh;

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket timeout");
        return -1;
    }

    while (bytes_sent < length) {
        if (socket->curr_win_size == 0) {
            printf("Window size is zero. Waiting for update...\n");
            microtcp_header_t probe_packet = {0};
            probe_packet.control = 0x10; // ACK flag
            probe_packet.seq_number = socket->seq_number;
            probe_packet.ack_number = socket->ack_number;
            probe_packet.checksum = crc32((uint8_t *)&probe_packet, sizeof(probe_packet));

            sendto(socket->sd, &probe_packet, sizeof(probe_packet), 0, NULL, 0);
            continue;
        }

        size_t segment_size = (length - bytes_sent > MICROTCP_MSS) ? MICROTCP_MSS : length - bytes_sent;
        if (segment_size > cwnd) {
            segment_size = cwnd;
        }

        microtcp_header_t data_packet;
        memset(&data_packet, 0, sizeof(data_packet));
        data_packet.control = 0x00;
        data_packet.seq_number = socket->seq_number;
        data_packet.ack_number = socket->ack_number;
        data_packet.data_len = segment_size;

        uint8_t sendbuf[MICROTCP_MSS + sizeof(microtcp_header_t)];
        memcpy(sendbuf, &data_packet, sizeof(data_packet));
        memcpy(sendbuf + sizeof(data_packet), (uint8_t *)buffer + bytes_sent, segment_size);
        data_packet.checksum = crc32(sendbuf, sizeof(data_packet) + segment_size);
        memcpy(sendbuf, &data_packet, sizeof(data_packet));

        if (sendto(socket->sd, sendbuf, sizeof(data_packet) + segment_size, flags, NULL, 0) < 0) {
            perror("Failed to send data packet");
            return -1;
        }

        printf("Sent %zu bytes, seq_number: %u\n", segment_size, data_packet.seq_number);

        while (1) {
            microtcp_header_t ack_packet;
            ssize_t received = recvfrom(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, NULL);

            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("Timeout occurred, resending packet\n");
                    ssthresh = cwnd / 2;
                    cwnd = MICROTCP_MSS;
                    break;
                }
                perror("Failed to receive ACK");
                return -1;
            }

            uint32_t received_checksum = ack_packet.checksum;
            ack_packet.checksum = 0;
            if (crc32((uint8_t *)&ack_packet, sizeof(ack_packet)) != received_checksum) {
                fprintf(stderr, "Invalid ACK packet received\n");
                continue;
            }

            if (ack_packet.ack_number == socket->seq_number) {
                duplicate_ack_count++;
                if (duplicate_ack_count >= 3) {
                    printf("3 duplicate ACKs detected, entering fast retransmit\n");
                    ssthresh = cwnd / 2;
                    cwnd = ssthresh + 1;
                    break;
                }
            } else if (ack_packet.ack_number > socket->seq_number) {
                socket->seq_number = ack_packet.ack_number;
                bytes_sent += segment_size;
                socket->curr_win_size -= segment_size;

                if (cwnd <= ssthresh) {
                    cwnd += MICROTCP_MSS;
                } else {
                    cwnd += MICROTCP_MSS * MICROTCP_MSS / cwnd;
                }

                duplicate_ack_count = 0;
                break;
            }
        }
    }

    socket->cwnd = cwnd;
    socket->ssthresh = ssthresh;

    return bytes_sent;
}

ssize_t 
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    if (!socket || socket->state != ESTABLISHED) {
        fprintf(stderr, "Socket not in ESTABLISHED state\n");
        return -1;
    }

    if (!buffer || length == 0) {
        fprintf(stderr, "Invalid buffer or length\n");
        return -1;
    }

    uint8_t recvbuf[MICROTCP_MSS + sizeof(microtcp_header_t)];
    ssize_t received = recvfrom(socket->sd, recvbuf, sizeof(recvbuf), flags, NULL, NULL);
    if (received < (ssize_t)sizeof(microtcp_header_t)) {
        fprintf(stderr, "Received invalid packet\n");
        return -1;
    }

    microtcp_header_t *header = (microtcp_header_t *)recvbuf;
    uint32_t received_checksum = header->checksum;
    header->checksum = 0;

    if (crc32(recvbuf, received) != received_checksum) {
        fprintf(stderr, "Checksum validation failed\n");
        return -1;
    }

    if (header->control & 0x01) { // FIN flag
        socket->state = CLOSING_BY_PEER;
        return -1;
    }

    size_t data_length = received - sizeof(microtcp_header_t);
    if (data_length > length) {
        fprintf(stderr, "Buffer too small for received data\n");
        return -1;
    }

    memcpy(buffer, recvbuf + sizeof(microtcp_header_t), data_length);
    socket->ack_number += data_length;

    microtcp_header_t ack_packet = {0};
    ack_packet.control = 0x10; // ACK flag
    ack_packet.seq_number = socket->seq_number;
    ack_packet.ack_number = socket->ack_number;
    ack_packet.window = MICROTCP_RECVBUF_LEN - socket->buf_fill_level;
    ack_packet.checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));
    sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, 0);

    return data_length;
}

