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
  printf("Socket created with state: %d\n", sock.state);
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

int 
microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
    printf("microtcp_connect: Starting connection process...\n");

    if (!socket || socket->state == INVALID) {
        fprintf(stderr, "microtcp_connect: Invalid microTCP socket\n");
        return -1;
    }

    printf("microtcp_connect: Initial socket state: %d\n", socket->state);

    // Prepare and send a SYN packet
    microtcp_header_t syn_packet;
    memset(&syn_packet, 0, sizeof(syn_packet));

    srand(time(NULL));
    syn_packet.control = 0x02;
    syn_packet.seq_number = rand() % UINT32_MAX;
    syn_packet.window = MICROTCP_WIN_SIZE;
    syn_packet.checksum = crc32((uint8_t *)&syn_packet, sizeof(syn_packet));

    printf("microtcp_connect: SYN Packet -> seq_number: %u, checksum: %u\n", syn_packet.seq_number, syn_packet.checksum);

    // Print raw SYN packet data
    printf("microtcp_connect: SYN Packet raw data:\n");
    uint8_t *raw_syn = (uint8_t *)&syn_packet;
    for (size_t i = 0; i < sizeof(syn_packet); ++i) {
        printf("%02X ", raw_syn[i]);
    }
    printf("\n");

    if (connect(socket->sd, address, address_len) < 0) {
        perror("microtcp_connect: Failed to connect UDP socket");
        return -1;
    }

    printf("microtcp_connect: Sending SYN packet...\n");
    if (microtcp_send(socket, &syn_packet, sizeof(syn_packet), 0) < 0) {
        perror("microtcp_connect: Failed to send SYN packet");
        return -1;
    }

    printf("microtcp_connect: State after sending SYN: %d\n", socket->state);

    // Wait for a SYN-ACK response
    microtcp_header_t syn_ack_packet;
    printf("microtcp_connect: Waiting for SYN-ACK packet...\n");
    if (microtcp_recv(socket, &syn_ack_packet, sizeof(syn_ack_packet), 0) < 0) {
        perror("microtcp_connect: Failed to receive SYN-ACK packet");
        return -1;
    }

    printf("microtcp_connect: Received SYN-ACK -> seq_number: %u, ack_number: %u, checksum: %u\n", 
           syn_ack_packet.seq_number, syn_ack_packet.ack_number, syn_ack_packet.checksum);

    // Validate SYN-ACK packet
    uint32_t received_checksum = syn_ack_packet.checksum;
    syn_ack_packet.checksum = 0;
    if (crc32((uint8_t *)&syn_ack_packet, sizeof(syn_ack_packet)) != received_checksum) {
        fprintf(stderr, "microtcp_connect: Checksum validation failed\n");
        return -1;
    }

    if (!(syn_ack_packet.control & 0x02) || !(syn_ack_packet.control & 0x10)) {
        fprintf(stderr, "microtcp_connect: Unexpected packet type\n");
        return -1;
    }

    printf("microtcp_connect: SYN-ACK received successfully\n");

    // Finalize connection
    socket->ack_number = syn_ack_packet.seq_number + 1;
    socket->seq_number = syn_ack_packet.ack_number;
    socket->init_win_size = syn_ack_packet.window;

    microtcp_header_t ack_packet;
    memset(&ack_packet, 0, sizeof(ack_packet));

    ack_packet.control = 0x10;
    ack_packet.seq_number = socket->seq_number;
    ack_packet.ack_number = socket->ack_number;
    ack_packet.window = MICROTCP_WIN_SIZE;
    ack_packet.checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

    printf("microtcp_connect: Sending final ACK packet...\n");
    if (microtcp_send(socket, &ack_packet, sizeof(ack_packet), 0) < 0) {
        perror("microtcp_connect: Failed to send ACK packet");
        return -1;
    }

    printf("microtcp_connect: Connection established\n");
    socket->state = ESTABLISHED;
    return 0;
}

int 
microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len) {
    printf("microtcp_accept: Waiting for connection...\n");

    if (!socket || socket->state != LISTEN) {
        fprintf(stderr, "microtcp_accept: Socket not in LISTEN state\n");
        return -1;
    }

    uint8_t buffer[MICROTCP_MSS + sizeof(microtcp_header_t)];
    microtcp_header_t *header = (microtcp_header_t *)buffer;

    while (1) {
        printf("microtcp_accept: Waiting for SYN packet...\n");
        printf("microtcp_accept: Current socket state: %d\n", socket->state);
        ssize_t received_len = microtcp_recv(socket, buffer, sizeof(buffer), 0);

        printf("microtcp_accept: Received length: %zd\n", received_len);

        if (received_len < (ssize_t)sizeof(microtcp_header_t)) {
            printf("microtcp_accept: Ignored invalid packet\n");
            continue;
        }

        printf("microtcp_accept: Validating SYN packet...\n");
        // Copy header and zero out checksum for validation
        microtcp_header_t received_header;
        memcpy(&received_header, header, sizeof(microtcp_header_t));
        received_header.checksum = 0;

        printf("microtcp_accept: Header checksum: %u, Calculated checksum: %u\n", 
               header->checksum, crc32((uint8_t *)&received_header, received_len));

        // Print raw received data
        printf("microtcp_accept: Received SYN packet raw data:\n");
        for (size_t i = 0; i < received_len; ++i) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");

        if ((header->control & 0x02) && crc32((uint8_t *)&received_header, received_len) == header->checksum) {
            printf("microtcp_accept: SYN packet received successfully\n");

            socket->seq_number = rand();
            socket->ack_number = header->seq_number + 1;
            socket->init_win_size = header->window;

            microtcp_header_t syn_ack = {
                .seq_number = socket->seq_number,
                .ack_number = socket->ack_number,
                .control = 0x12,
                .window = MICROTCP_WIN_SIZE,
                .checksum = 0
            };
            syn_ack.checksum = crc32((uint8_t *)&syn_ack, sizeof(syn_ack));

            printf("microtcp_accept: SYN-ACK Packet -> seq_number: %u, ack_number: %u, window: %u\n", 
                   syn_ack.seq_number, syn_ack.ack_number, syn_ack.window);

            if (microtcp_send(socket, &syn_ack, sizeof(syn_ack), 0) < 0) {
                perror("microtcp_accept: Failed to send SYN-ACK");
                return -1;
            }
            break;
        } else {
            printf("microtcp_accept: Invalid SYN packet or checksum mismatch\n");
        }
    }
    return 0;
}

int 
microtcp_shutdown(microtcp_sock_t *socket, int how) {
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
        fin_packet.checksum = crc32((uint8_t *)&fin_packet, sizeof(fin_packet));

        if (microtcp_send(socket, &fin_packet, sizeof(fin_packet), 0) < 0) {
            perror("Failed to send FIN packet");
            return -1;
        }

        printf("FIN packet sent, seq_number: %u\n", fin_packet.seq_number);

        // Step 2: Client waits for ACK from server
        microtcp_header_t ack_packet;
        if (microtcp_recv(socket, &ack_packet, sizeof(ack_packet), 0) < 0) {
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
        if (microtcp_recv(socket, &server_fin_packet, sizeof(server_fin_packet), 0) < 0) {
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
        client_ack_packet.checksum = crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet));

        if (microtcp_send(socket, &client_ack_packet, sizeof(client_ack_packet), 0) < 0) {
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
        ack_packet.checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

        if (microtcp_send(socket, &ack_packet, sizeof(ack_packet), 0) < 0) {
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
        fin_packet.checksum = crc32((uint8_t *)&fin_packet, sizeof(fin_packet));

        if (microtcp_send(socket, &fin_packet, sizeof(fin_packet), 0) < 0) {
            perror("Failed to send FIN");
            return -1;
        }

        printf("Server FIN sent\n");

        // Step 3: Server waits for ACK from client
        microtcp_header_t client_ack_packet;
        if (microtcp_recv(socket, &client_ack_packet, sizeof(client_ack_packet), 0) < 0) {
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

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    printf("%d\n", socket->state);
    if (!socket || (socket->state != ESTABLISHED && socket->state != CLOSED && socket->state != LISTEN)) {
        fprintf(stderr, "microtcp_send: Socket not in a valid state\n");
        return -1;
    }

    if (!buffer || length == 0) {
        fprintf(stderr, "microtcp_send: Invalid buffer or length\n");
        return -1;
    }

    size_t bytes_sent = 0;
    size_t cwnd = socket->cwnd;
    size_t ssthresh = socket->ssthresh;

    printf("microtcp_send: Starting data transmission\n");

    while (bytes_sent < length) {
        size_t segment_size = (length - bytes_sent > MICROTCP_MSS) ? MICROTCP_MSS : length - bytes_sent;
        microtcp_header_t data_packet = {0};
        data_packet.control = 0x00; // Data flag
        data_packet.seq_number = socket->seq_number;
        data_packet.ack_number = socket->ack_number;
        data_packet.data_len = segment_size;

        uint8_t sendbuf[MICROTCP_MSS + sizeof(microtcp_header_t)];
        memcpy(sendbuf, &data_packet, sizeof(data_packet));
        memcpy(sendbuf + sizeof(data_packet), (uint8_t *)buffer + bytes_sent, segment_size);
        data_packet.checksum = crc32(sendbuf, sizeof(data_packet) + segment_size);
        memcpy(sendbuf, &data_packet, sizeof(data_packet));

        if (send(socket->sd, sendbuf, sizeof(data_packet) + segment_size, flags) < 0) {
            perror("microtcp_send: Failed to send data packet");
            return -1;
        }

        printf("Sent %zu bytes, seq_number: %u\n", segment_size, data_packet.seq_number);
        bytes_sent += segment_size;
        socket->seq_number += segment_size;
    }

    printf("microtcp_send: Transmission complete. Total bytes sent: %zu\n", bytes_sent);

    return bytes_sent;
}

ssize_t 
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    // Debug: Check socket state
    printf("microtcp_recv: Socket state before recv: %d\n", socket->state);

    if (!socket || (socket->state != ESTABLISHED && socket->state != LISTEN && socket->state != CLOSED)) {
        fprintf(stderr, "microtcp_recv: Socket not in a valid state for receiving packets\n");
        return -1;
    }

    if (!buffer || length == 0) {
        fprintf(stderr, "microtcp_recv: Invalid buffer or length\n");
        return -1;
    }

    printf("microtcp_recv: Waiting to receive data...\n");

    uint8_t recvbuf[MICROTCP_MSS + sizeof(microtcp_header_t)];
    ssize_t received = recvfrom(socket->sd, recvbuf, sizeof(recvbuf), flags, NULL, NULL);
    if (received < (ssize_t)sizeof(microtcp_header_t)) {
        fprintf(stderr, "microtcp_recv: Received invalid packet\n");
        return -1;
    }

    printf("microtcp_recv: Packet received, size: %ld bytes\n", received);

    microtcp_header_t *header = (microtcp_header_t *)recvbuf;
    uint32_t received_checksum = header->checksum;
    header->checksum = 0;

    if (crc32(recvbuf, received) != received_checksum) {
        fprintf(stderr, "microtcp_recv: Checksum validation failed\n");
        return -1;
    }

    if (header->control & 0x01) { // FIN flag
        printf("microtcp_recv: FIN packet received\n");
        socket->state = CLOSING_BY_PEER;
        return -1;
    }

    size_t data_length = received - sizeof(microtcp_header_t);
    if (data_length > length) {
        fprintf(stderr, "microtcp_recv: Buffer too small for received data\n");
        return -1;
    }

    memcpy(buffer, recvbuf + sizeof(microtcp_header_t), data_length);
    socket->ack_number += data_length;

    printf("microtcp_recv: Data extracted, length: %zu bytes\n", data_length);

    microtcp_header_t ack_packet = {0};
    ack_packet.control = 0x10; // ACK flag
    ack_packet.seq_number = socket->seq_number;
    ack_packet.ack_number = socket->ack_number;
    ack_packet.window = MICROTCP_RECVBUF_LEN - socket->buf_fill_level;
    ack_packet.checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

    sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, 0);

    printf("microtcp_recv: ACK sent, ack_number: %u\n", ack_packet.ack_number);

    return data_length;
}



