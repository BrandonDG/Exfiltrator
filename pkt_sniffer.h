// Name:    Brandon Gillespie and Justen DePourcq
// Date:    October 19th, 2018
// Class:   COMP8505
// Assn:    Assignment 3 - Backdoor
// Purpose: Header file to hold includes, prototypes, and structures for the
// backdoor_client.c program and pck_cap.c program.

#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SIZE_ETHERNET 14

// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

// Function Prototypes
void packet_handler(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet);

// Send struct that is used to pass necessary variables to callback function.
struct send_struct {
  int sd;
  int data_size;
  struct sockaddr_in server;
  char *key;
  int klen;
} send_struct;
