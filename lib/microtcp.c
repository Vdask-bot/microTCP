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
#include <netinet/in.h>
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
    syn_packet.control = 0x02; // SYN flag
    syn_packet.seq_number = rand() % UINT32_MAX;
    syn_packet.window = MICROTCP_WIN_SIZE;
    syn_packet.checksum = htonl(crc32((uint8_t *)&syn_packet, sizeof(syn_packet)));

    printf("microtcp_connect: SYN Packet -> seq_number: %u, checksum: %u\n", syn_packet.seq_number, ntohl(syn_packet.checksum));

    // Send SYN packet
    if (sendto(socket->sd, &syn_packet, sizeof(syn_packet), 0, address, address_len) < 0) {
        perror("microtcp_connect: Failed to send SYN packet");
        return -1;
    }
    printf("SYN Packet Sent (Raw Data):\n");
    for (size_t i = 0; i < sizeof(syn_packet); i++) {
        printf("%02X ", ((uint8_t *)&syn_packet)[i]);
    }
    printf("\n");

    printf("microtcp_connect: SYN packet sent. Waiting for SYN-ACK...\n");

    // Wait for SYN-ACK response
    microtcp_header_t syn_ack_packet;
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);

    if (recvfrom(socket->sd, &syn_ack_packet, sizeof(syn_ack_packet), 0, (struct sockaddr *)&recv_addr, &recv_addr_len) < 0) {
        perror("microtcp_connect: Failed to receive SYN-ACK packet");
        return -1;
    }

    printf("microtcp_connect: Received SYN-ACK -> seq_number: %u, ack_number: %u, checksum: %u\n", 
           syn_ack_packet.seq_number, syn_ack_packet.ack_number, ntohl(syn_ack_packet.checksum));

    // Validate SYN-ACK
    uint32_t received_checksum = ntohl(syn_ack_packet.checksum);
    syn_ack_packet.checksum = 0;
    uint32_t calculated_checksum = crc32((uint8_t *)&syn_ack_packet, sizeof(syn_ack_packet));

    printf("microtcp_connect: Validating SYN-ACK checksum...\n");
    printf("microtcp_connect: Received Checksum: %u, Calculated Checksum: %u\n", 
           received_checksum, calculated_checksum);

    if (calculated_checksum != received_checksum) {
        fprintf(stderr, "microtcp_connect: Checksum validation failed. Expected: %u, Got: %u\n",
                received_checksum, calculated_checksum);
        return -1;
    }

    if (!(syn_ack_packet.control & 0x12)) { // SYN and ACK flags
        fprintf(stderr, "microtcp_connect: Unexpected packet type\n");
        return -1;
    }

    printf("microtcp_connect: SYN-ACK received successfully\n");

    // Send final ACK packet
    socket->ack_number = syn_ack_packet.seq_number + 1;
    socket->seq_number = syn_ack_packet.ack_number;

    microtcp_header_t ack_packet;
    memset(&ack_packet, 0, sizeof(ack_packet));

    ack_packet.control = 0x10; // ACK flag
    ack_packet.seq_number = htonl(socket->seq_number);
    ack_packet.ack_number = htonl(socket->ack_number);
    ack_packet.window = htonl(MICROTCP_WIN_SIZE);
    ack_packet.checksum = 0; 
    ack_packet.checksum = htonl(crc32((uint8_t *)&ack_packet, sizeof(ack_packet)));

    printf("microtcp_connect: Sending final ACK packet...\n");
    if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, address, address_len) < 0) {
        perror("microtcp_connect: Failed to send ACK packet");
        return -1;
    }

    printf("microtcp_connect: Connection established\n");

    // Connect socket to bind destination address for subsequent sends
    if (connect(socket->sd, address, address_len) < 0) {
        perror("microtcp_connect: Failed to bind socket to destination address");
        return -1;
    }

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
        printf("Received Packet (Raw Data):\n");
        for (size_t i = 0; i < received_len; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");

        printf("microtcp_accept: Validating SYN packet...\n");
        uint32_t received_checksum = ntohl(header->checksum);
        header->checksum = 0; // Reset checksum για υπολογισμό
        uint32_t calculated_checksum = crc32(buffer, sizeof(microtcp_header_t));

        printf("microtcp_accept: Expected Checksum: %u, Calculated Checksum: %u\n",
               received_checksum, calculated_checksum);

        if (calculated_checksum != received_checksum) {
            fprintf(stderr, "Checksum validation failed. Expected: %u, Got: %u\n",
                    received_checksum, calculated_checksum);
            continue;
        }

        if (header->control & 0x02) { // SYN flag
            printf("microtcp_accept: SYN packet received successfully\n");

            socket->seq_number = rand();
            socket->ack_number = ntohl(header->seq_number) + 1;

            microtcp_header_t syn_ack = {
                .seq_number = htonl(socket->seq_number),
                .ack_number = htonl(socket->ack_number),
                .control = 0x12, // SYN and ACK flags
                .window = htonl(MICROTCP_WIN_SIZE),
                .checksum = 0
            };
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

            printf("Received Final ACK (Raw Data):\n");
            for (size_t i = 0; i < received_len; i++) {
                printf("%02X ", buffer[i]);
            }
            printf("\n");

            received_checksum = ntohl(header->checksum);
            header->checksum = 0; // Reset checksum για validation
            calculated_checksum = crc32(buffer, sizeof(microtcp_header_t));

            printf("microtcp_accept: Final ACK - Expected Checksum: %u, Calculated Checksum: %u\n",
                   received_checksum, calculated_checksum);

            if (calculated_checksum != received_checksum || !(header->control & 0x10)) {
                fprintf(stderr, "microtcp_accept: Final ACK validation failed\n");
                return -1;
            }

            printf("microtcp_accept: Connection established\n");

            // Συνδέουμε το socket στη διεύθυνση του client
            if (connect(socket->sd, (struct sockaddr *)&client_addr, client_addr_len) < 0) {
                perror("microtcp_accept: Failed to bind socket to client address");
                return -1;
            }

            socket->state = ESTABLISHED;
            return 0;
        }
    }
}


int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    if (!socket || (socket->state != ESTABLISHED && socket->state != CLOSING_BY_PEER)) {
        fprintf(stderr, "Socket not in a valid state for shutdown. Current state: %d\n", socket->state);
        return -1;
    }

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);

    uint32_t received_checksum = 0;
    uint32_t calculated_checksum = 0;

    if (getpeername(socket->sd, (struct sockaddr *)&peer_addr, &peer_addr_len) < 0) {
        perror("Failed to get peer address");
        return -1;
    }

    printf("Shutting down connection. Current state: %d\n", socket->state);

    if (socket->state == ESTABLISHED) {
        // CLIENT LOGIC
        microtcp_header_t fin_packet = {0};
        fin_packet.control = 0x01; // FIN flag
        fin_packet.seq_number = htonl(socket->seq_number++);
        fin_packet.ack_number = htonl(socket->ack_number);
        fin_packet.checksum = htonl(crc32((uint8_t *)&fin_packet, sizeof(fin_packet)));

        printf("Sending FIN packet: seq_number=%u, ack_number=%u, checksum=%u\n",
               ntohl(fin_packet.seq_number), ntohl(fin_packet.ack_number), ntohl(fin_packet.checksum));

        if (sendto(socket->sd, &fin_packet, sizeof(fin_packet), 0, (struct sockaddr *)&peer_addr, peer_addr_len) < 0) {
            perror("Failed to send FIN packet");
            return -1;
        }

        // Wait for ACK
        microtcp_header_t ack_packet;
        if (recvfrom(socket->sd, &ack_packet, sizeof(ack_packet), 0, NULL, NULL) < 0) {
            perror("Failed to receive ACK packet");
            return -1;
        }

        received_checksum = ntohl(ack_packet.checksum);
        ack_packet.checksum = 0;
        calculated_checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

        printf("Received ACK: checksum=%u, calculated_checksum=%u\n",
               received_checksum, calculated_checksum);

        if (calculated_checksum != received_checksum || !(ack_packet.control & 0x10)) {
            fprintf(stderr, "Invalid ACK packet received\n");
            return -1;
        }

        // Wait for FIN from server
        microtcp_header_t server_fin_packet;
        if (recvfrom(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0, NULL, NULL) < 0) {
            perror("Failed to receive FIN packet from server");
            return -1;
        }

        received_checksum = ntohl(server_fin_packet.checksum);
        server_fin_packet.checksum = 0;
        calculated_checksum = crc32((uint8_t *)&server_fin_packet, sizeof(server_fin_packet));

        printf("Received FIN: checksum=%u, calculated_checksum=%u\n",
               received_checksum, calculated_checksum);

        if (calculated_checksum != received_checksum || 
            !(server_fin_packet.control & 0x01) && !(server_fin_packet.control & 0x11)) {
            fprintf(stderr, "Invalid FIN packet received\n");
            fprintf(stderr, "Debug Information:\n");
            fprintf(stderr, "  Received checksum: %u\n", received_checksum);
            fprintf(stderr, "  Calculated checksum: %u\n", calculated_checksum);
            fprintf(stderr, "  Control flags in FIN packet: %u\n", server_fin_packet.control);
            return -1;
        }

        // Send ACK for FIN
        microtcp_header_t client_ack_packet = {0};
        client_ack_packet.control = 0x10; // ACK flag
        client_ack_packet.seq_number = htonl(socket->seq_number++);
        client_ack_packet.ack_number = htonl(ntohl(server_fin_packet.seq_number) + 1);
        client_ack_packet.checksum = htonl(crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet)));

        printf("Sending ACK for FIN: seq_number=%u, ack_number=%u, checksum=%u\n",
               ntohl(client_ack_packet.seq_number), ntohl(client_ack_packet.ack_number), ntohl(client_ack_packet.checksum));

        if (sendto(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, (struct sockaddr *)&peer_addr, peer_addr_len) < 0) {
            perror("Failed to send ACK for FIN");
            return -1;
        }

        socket->state = CLOSED;
        printf("Connection successfully closed by client\n");
        return 0;
    }

    if (socket->state == CLOSING_BY_PEER) {
        // SERVER LOGIC
        printf("Server received FIN. Sending ACK...\n");

        microtcp_header_t ack_packet = {0};
        ack_packet.control = 0x10; // ACK flag
        ack_packet.seq_number = htonl(socket->seq_number++);
        ack_packet.ack_number = htonl(socket->ack_number);
        ack_packet.checksum = htonl(crc32((uint8_t *)&ack_packet, sizeof(ack_packet)));

        if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&peer_addr, peer_addr_len) < 0) {
            perror("Failed to send ACK for FIN");
            return -1;
        }

        printf("Server sending its own FIN...\n");

        microtcp_header_t server_fin_packet = {0};
        server_fin_packet.control = 0x01; // FIN flag
        server_fin_packet.seq_number = htonl(socket->seq_number++);
        server_fin_packet.ack_number = htonl(socket->ack_number);
        server_fin_packet.checksum = htonl(crc32((uint8_t *)&server_fin_packet, sizeof(server_fin_packet)));

        printf("Server FIN packet details: seq_number=%u, ack_number=%u, checksum=%u\n",
                ntohl(server_fin_packet.seq_number),
                ntohl(server_fin_packet.ack_number),
                ntohl(server_fin_packet.checksum));

        if (sendto(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0, (struct sockaddr *)&peer_addr, peer_addr_len) < 0) {
            perror("Failed to send FIN packet");
            return -1;
        }

        printf("Waiting for client to send final ACK...\n");

        microtcp_header_t client_ack_packet;
        if (recvfrom(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, NULL, NULL) < 0) {
            perror("Failed to receive final ACK from client");
            return -1;
        }

        received_checksum = ntohl(client_ack_packet.checksum);
        client_ack_packet.checksum = 0;
        calculated_checksum = crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet));

        printf("Received final ACK: checksum=%u, calculated_checksum=%u\n",
               received_checksum, calculated_checksum);

        if (calculated_checksum != received_checksum || !(client_ack_packet.control & 0x10)) {
            fprintf(stderr, "Invalid final ACK received\n");
            return -1;
        }

        socket->state = CLOSED;
        printf("Connection successfully closed by server\n");
        return 0;
    }

    return -1;
}

ssize_t microtcp_send(microtcp_socket *sock, const void *buf, size_t len) {
    size_t total_sent = 0;
    size_t chunk_size;
    size_t cwnd = sock->cwnd;  // Congestion window size (initial value)
    size_t ssthresh = sock->ssthresh;  // Slow start threshold
    size_t current_seq_number = sock->seq_number;
    size_t last_sent_seq_number = current_seq_number;
    size_t ack_number = 0;  // Initialize ACK number
    size_t duplicate_ack_count = 0;  // Counter for duplicate ACKs

    // Send data until all of it is sent
    while (total_sent < len) {
        chunk_size = (len - total_sent > cwnd) ? cwnd : (len - total_sent);  // Send data based on congestion window

        // Simulate sending the chunk
        ssize_t sent = socket_send(sock->fd, (char*)buf + total_sent, chunk_size);  // Use your socket send function

        if (sent < 0) {
            // Handle send error (e.g., congestion or timeout)
            return -1;
        }

        total_sent += sent;
        current_seq_number += sent;
        last_sent_seq_number = current_seq_number;  // Update last sent sequence number

        // Wait for ACK (simulate waiting for ACK here)
        bool ack_received = wait_for_ack(sock, &ack_number);  // Placeholder for actual ACK waiting mechanism

        if (ack_received) {
            // Check for duplicate ACKs
            if (ack_number == last_sent_seq_number) {
                duplicate_ack_count++;
                if (duplicate_ack_count >= 3) {
                    // If we get 3 duplicate ACKs, retransmit the last packet
                    printf("Duplicate ACK detected, retransmitting packet...\n");
                    socket_send(sock->fd, (char*)buf + total_sent - chunk_size, chunk_size);  // Retransmit last chunk
                    duplicate_ack_count = 0;  // Reset duplicate ACK count after retransmission
                }
            } else {
                duplicate_ack_count = 0;  // Reset if we receive a new ACK

                // In slow start, increase the congestion window additively
                if (cwnd < ssthresh) {
                    cwnd += 1;
                } else {
                    // In congestion avoidance, increase the congestion window additively
                    cwnd += cwnd / 10;
                }
            }
        } else {
            // Timeout occurred, retransmit the last packet
            printf("Timeout occurred, retransmitting last packet...\n");
            socket_send(sock->fd, (char*)buf + total_sent - chunk_size, chunk_size);  // Retransmit last chunk
        }

        // Log window size for debugging
        printf("Current congestion window (cwnd): %zu\n", cwnd);
    }

    // Return the total number of bytes sent
    return total_sent;
}


ssize_t microtcp_recv(microtcp_sock_t *sock, void *buffer, size_t length) {
    ssize_t received_bytes = 0;
    microtcp_packet_t packet;

    while (received_bytes < length) {
        // Wait for incoming data
        packet = receive_packet(sock);

        // If we received a FIN packet, handle connection termination
        if (packet.flags & FIN_FLAG) {
            send_ack(sock, packet.seq_number + 1);
            break;  // Stop receiving data
        }

        // Extract data from the received packet and add it to the buffer
        size_t data_size = extract_data(packet, buffer + received_bytes, length - received_bytes);
        received_bytes += data_size;

        // **Flow control**: After receiving, check and update the receive window
        sock->recv_window -= data_size;

        // Acknowledge the received packet
        send_ack(sock, packet.seq_number + data_size);

        // **Flow control**: Wait if the receive window is full
        while (sock->recv_window == 0) {
            wait_for_application_to_consume_data();
            sock->recv_window = get_available_buffer_space();  // Update window size
        }
    }

    return received_bytes;
}




