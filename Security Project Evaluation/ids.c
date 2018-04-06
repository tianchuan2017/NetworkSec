// IDS
// Group 1

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>


#include "utils.h"


char *ScanData(char *data, int length, transport signatures[])
{
  if(strlen(data) ==1){
      return "";
  }
	char *id;
	for(;signatures->size != 0; signatures++){
		id = malloc(signatures->size+1);
		memset(id,'\0',signatures->size);
		memcpy(id, signatures->message, signatures->size);
		signatures++;
		char pattern[signatures->size+1];
		memset(pattern,'\0',sizeof(pattern));
		memcpy(pattern, signatures->message,signatures->size);
		if(memmem(data, length-1, pattern,signatures->size)){
			printf("This signature with id %s matched: %s this piece of data %s\n", id, pattern, data);
			return id;
		}
		free(id);
	}

  return "";
}

void WriteToLog(char *ids_logname, char *id, char*ip)
{
	FILE *ids_log = fopen(ids_logname, "a");
	time_t t;
	time(&t);
	struct tm *tm = localtime(&t);
	char time_buffer[80];
	strftime(time_buffer, 80, "%c", tm);

	//log message format is: <id> <ip> <timestamp>\n
	char message_to_write[strlen(id) + 1 + strlen(ip) + 1 + sizeof(time_buffer) +2];
	sprintf(message_to_write,"%s %s %s\n", id, ip, time_buffer);
	fwrite(message_to_write, sizeof(char), strlen(message_to_write)+1,ids_log);
	fclose(ids_log);
}

void IDSHandler(int client_socket, transport ids_signatures[], char * ftp_dir, char * ids_logname,char *ip)
{
	int actual_receive_size;
	int expected_receive_size;
	int send_size;
	int size_holder;
  int32_t net_size;
  int32_t size;

  char *send_buffer;

  transport response;
  char *message;

	char buffer[CHUNK];
	memset(buffer, 0, sizeof(buffer));

	char *size_buffer = (char*)&net_size;
	memset(size_buffer, 0, sizeof(int32_t));


	while(1)
	{
		printf("IN IDS RECEIVING LOOP\n");
		if(recv(client_socket, size_buffer, sizeof(int32_t), 0) <= 0){
			printf("READ 0 bytes FROM CLOSED CLIENT SOCKET\n");
			break;
		}

		size = ntohl(net_size);
		printf("Expected Size: %d\n", size);
		size_holder = 0;
		message = (char *) calloc(size, sizeof(char));
		printf("RECEIVE LOOP START:\n");
		while(size_holder < size)
		{
			memset(buffer, 0, sizeof(buffer));
			expected_receive_size = ((size-size_holder) < CHUNK) ? (size-size_holder): CHUNK;
			// printf("expected_receive_size: %d size_holder: %d size: %d\n", expected_receive_size, size_holder, size);
			actual_receive_size = recv(client_socket, buffer, expected_receive_size, 0);
			// printf("actual_receive_size: %d\n",actual_receive_size);

			if(actual_receive_size <= 0){
				printf("READ 0 bytes FROM CLOSED CLIENT SOCKET\n");
				goto break_from_receiving;
			}
			// printf("Receive buffer content: %s\n", buffer);
			char *scan_result =ScanData(buffer, actual_receive_size, ids_signatures);
			if(strlen(scan_result) ==0)
			{
				memcpy((message+size_holder), buffer, actual_receive_size);
				size_holder += actual_receive_size;
			} else {
				WriteToLog(ids_logname, scan_result, ip);
				free(scan_result);

				size -= actual_receive_size;
			}

		}
		printf("\nRECEIVE LOOP END\nSize expected: %d, Size received: %d\n", size, size_holder);

		transport input = {size, message};
		response = FTPExecute(input, ftp_dir);

		send_buffer = (char *) calloc(response.size, sizeof(char));

		int original_pos;
		int send_buffer_pos = 0;

		for(original_pos = 0; original_pos < response.size; original_pos+=CHUNK)
		{
			send_size = ((response.size-original_pos) < CHUNK) ? (response.size-original_pos): CHUNK;
			char *scan_result = ScanData((response.message+size_holder), send_size, ids_signatures);
			if(strlen(scan_result) == 0)
			{
				memcpy((send_buffer + send_buffer_pos), (response.message+original_pos), send_size);
				send_buffer_pos += send_size;
			} else {
				WriteToLog(ids_logname, scan_result, ip);
			}
		}

		printf("\nSEND LOOP END\nsize expedted: %d, ofset in original: %d, size sent: %d\n", response.size, original_pos, send_buffer_pos);

		net_size = htonl(send_buffer_pos);
		send(client_socket, &net_size, sizeof(int32_t), 0);
		send(client_socket, send_buffer, send_buffer_pos, 0);

    printf("Message sent!\n\n");
		free(message);

	}
	break_from_receiving:
	printf("GOING TO WAIT FOR NEW CONNECTION\n");
}
