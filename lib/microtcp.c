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
#include "microtcp.h"
#include "../utils/crc32.h"

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  microtcp_sock_t sock;

  // Create the UDP socket
  sock.sd = socket(domain, type, protocol);
  if (sock.sd < 0) {
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
  if (!sock.recvbuf) {
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

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{
  if (!socket || socket->state == INVALID) {
      fprintf(stderr, "Invalid microTCP socket\n");
      return -1;
  }

  // Attempt to bind the underlying UDP socket
  if (bind(socket->sd, address, address_len) < 0) {
      perror("bind");
      return -1; 
  }

  // If binding is successful, update the state if necessary
  socket->state = LISTEN; 
  return 0;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  if (!socket || socket->state == INVALID) {
      fprintf(stderr, "Invalid microTCP socket\n");
      return -1;
  }

  // Step 1: Prepare and send a packet to initiate the connection
  microtcp_header_t syn_packet;
  memset(&syn_packet, 0, sizeof(syn_packet));

  srand(time(NULL)); // Ensure random initialization for the sequence number
  syn_packet.control = 0x02; // SYN flag
  syn_packet.seq_number = rand() % UINT32_MAX; // Random sequence number
  syn_packet.checksum = 0;
  syn_packet.checksum = crc32((uint8_t*)&syn_packet, sizeof(syn_packet)); // Calculate checksum

  if (sendto(socket->sd, &syn_packet, sizeof(syn_packet), 0, address, address_len) < 0) {
    perror("Failed to send packet");
    return -1;
  }

  // Step 2: Wait for a response from the other side
  microtcp_header_t syn_ack_packet;
  socklen_t addr_len = address_len;
  if (recvfrom(socket->sd, &syn_ack_packet, sizeof(syn_ack_packet), 0, (struct sockaddr*)address, &addr_len) < 0) {
    perror("Failed to receive response packet");
    return -1;
  }

  // Validate the received packet
  uint32_t received_checksum = syn_ack_packet.checksum;
  syn_ack_packet.checksum = 0; // Reset checksum for validation
  if (crc32((uint8_t*)&syn_ack_packet, sizeof(syn_ack_packet)) != received_checksum) {
      fprintf(stderr, "Checksum validation failed\n");
      return -1;
  }

  // Check flags in the response packet
  if (!(syn_ack_packet.control & 0x02) || !(syn_ack_packet.control & 0x10)) { // SYN and ACK must be set
      fprintf(stderr, "Unexpected packet type\n");
      return -1;
  }

  // Step 3: Update connection parameters
  socket->ack_number = syn_ack_packet.seq_number + 1;
  socket->seq_number = syn_ack_packet.ack_number;

  // Step 4: Send the final acknowledgment to confirm the connection
  microtcp_header_t ack_packet;
  memset(&ack_packet, 0, sizeof(ack_packet));

  ack_packet.control = 0x10; // ACK flag
  ack_packet.seq_number = socket->seq_number;
  ack_packet.ack_number = socket->ack_number;
  ack_packet.checksum = 0;
  ack_packet.checksum = crc32((uint8_t*)&ack_packet, sizeof(ack_packet));

  if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, address, address_len) < 0) {
      perror("Failed to send acknowledgment");
      return -1;
  }

  // Finalize connection setup
  socket->state = ESTABLISHED;
  return 0;
}

int 
microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                socklen_t address_len) 
{
    if (!socket || socket->state != LISTEN) {
        fprintf(stderr, "Socket not in LISTEN state\n");
        return -1;
    }

    uint8_t buffer[MICROTCP_MSS + sizeof(microtcp_header_t)];
    microtcp_header_t *header = (microtcp_header_t *)buffer;

    // Wait for a SYN packet
    while (1) {
        ssize_t received_len = recvfrom(socket->sd, buffer, sizeof(buffer), 0, address, &address_len);
        if (received_len < sizeof(microtcp_header_t)) {
            continue; // Ignore invalid packets
        }

        // Verify SYN and checksum
        if ((header->control & (1 << 14)) && crc32(buffer, received_len) == header->checksum) {
            // Respond with SYN-ACK
            socket->seq_number = rand();
            socket->ack_number = header->seq_number + 1;

            microtcp_header_t syn_ack = {
                .seq_number = socket->seq_number,
                .ack_number = socket->ack_number,
                .control = (1 << 15) | (1 << 14), // SYN and ACK
                .checksum = 0
            };
            syn_ack.checksum = crc32((uint8_t *)&syn_ack, sizeof(syn_ack));

            if (sendto(socket->sd, &syn_ack, sizeof(syn_ack), 0, address, address_len) < 0) {
                return -1;
            }
            break; // SYN-ACK sent, exit loop
        }
    }

    // Wait for ACK
    while (1) {
        ssize_t received_len = recvfrom(socket->sd, buffer, sizeof(buffer), 0, address, &address_len);
        if (received_len < sizeof(microtcp_header_t)) {
            continue; // Ignore invalid packets
        }

        // Verify ACK and checksum
        if ((header->control & (1 << 15)) && crc32(buffer, received_len) == header->checksum) {
            if (header->ack_number == socket->seq_number + 1) {
                socket->state = ESTABLISHED; // Connection established
                return 0;
            }
        }
    }

    return -1; // If handshake fails
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  if (!socket || socket->state != ESTABLISHED) {
    fprintf(stderr, "Socket not in ESTABLISHED state\n");
    return -1;
  }

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
  if (crc32((uint8_t *)&ack_packet, sizeof(ack_packet)) != received_checksum) {
      fprintf(stderr, "Invalid checksum in ACK packet\n");
      return -1;
  }

  if (!(ack_packet.control & 0x10)) { // Check if ACK flag is set
    fprintf(stderr, "Received packet is not an ACK\n");
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
  if (crc32((uint8_t *)&server_fin_packet, sizeof(server_fin_packet)) != received_checksum) {
    fprintf(stderr, "Invalid checksum in FIN packet\n");
    return -1;
  }

  if (!(server_fin_packet.control & 0x01)) { // Check if FIN flag is set
    fprintf(stderr, "Received packet is not a FIN\n");
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
    perror("Failed to send ACK for FIN");
    return -1;
  }

  printf("ACK sent to server's FIN, ack_number: %u\n", client_ack_packet.ack_number);

  // Step 5: Finalize the connection state
  socket->state = CLOSED;
  printf("Connection closed\n");

  return 0;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  /* Your code here */
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Your code here */
}
