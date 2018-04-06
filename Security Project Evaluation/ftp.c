// FTP
// Group 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

//Packet format: <mode><space><command>
transport FTPExecute(transport input, char *ftp_dir)
{
	transport response = {input.size, input.message};
	//first character is the mode
	char mode = input.message[0];

	switch(mode) {
		//get command
		case 'G': {
			//byte 3 and on are the filename
			int file_name_size = strlen(ftp_dir) + strlen(input.message+2) +1;
			char file_path[file_name_size];
			//We can use sprintf and %s because null bytes are illegal in filenames in Unix
			sprintf(file_path, "%s%s", ftp_dir,input.message+2);
			// Open the file
			FILE *get_file = fopen(file_path, "r");
			if(get_file == NULL){
				char *response_message = "Couldn't open file\n";
				size_t message_size = strlen(response_message +1);
				response.message = malloc(message_size);
				strcpy(response.message, response_message);
				response.size = message_size;
			} else {
				//get the size of the file
				struct stat sb;
				stat(file_path, &sb);
				int file_size = sb.st_size;
				// Read in the hash
				char hash_name[strlen(file_path) + 6];
				sprintf(hash_name, "%s_hash", file_path);
				FILE *hash_file = fopen(hash_name, "r");
				response.message = (char *) malloc(file_size+64);
				memset(response.message, '\0', file_size+64);
				size_t nread = 0;
				if(hash_file != NULL){
					nread += fread(response.message, sizeof(char), 64, hash_file);
				}

				//read the file into response.message
				for(; nread <file_size+64;
					(nread+= fread(response.message+nread, sizeof(char), CHUNK, get_file)));
				response.size = file_size+64;
				fclose(get_file);
			}
		}
		break;
		//put command
		case 'P' : {
			//get the file size and name
			int file_size = input.size- strlen(input.message)-1- 64;
			int file_name_size = strlen(ftp_dir) + strlen(input.message+2) +1;
			char file_path[file_name_size];
			sprintf(file_path, "%s%s",ftp_dir,input.message+2);
			// Get filename of the hash
			char hash_path[file_name_size+5];
			sprintf(hash_path, "%s_hash",file_path);

			// Get the hash
			FILE *hash_file = fopen(hash_path, "w");
			if(hash_file == NULL){
				char *response_message = "Couldn't open file for writing on ftp server\n";
				size_t message_size = strlen(response_message +1);
				response.message = malloc(message_size);
				strcpy(response.message, response_message);
				response.size = message_size;
			} else{
				fwrite(input.message + strlen(input.message)+1, sizeof(char), 64, hash_file);
				fclose(hash_file);
			}
			FILE *put_file = fopen(file_path, "w");
			if(file_path == NULL){
				char *response_message = "Couldn't open file for writing on ftp server\n";
				size_t message_size = strlen(response_message +1);
				response.message = malloc(message_size);
				strcpy(response.message, response_message);
				response.size = message_size;
			} else{
				size_t nwrite;
				//read the message into the file
				//sending the message 3 times plus junk in input.message so we need to use file size
				for(nwrite =0; nwrite <file_size;
					(nwrite+= fwrite(input.message+strlen(input.message)+1 + 64 +nwrite, sizeof(char), file_size, put_file)));
				char *response_message = "Wrote file\n";
				size_t message_size = strlen(response_message +1);
				response.message = malloc(message_size);
				strcpy(response.message, response_message);
				response.size = message_size;
				fclose(put_file);
			}
		}
		break;
		//ls command
		case 'L': {
			char command[strlen("/bin/ls ") + strlen(ftp_dir)+2];
			sprintf(command,"/bin/ls %s;", ftp_dir);
			//TODO: protect against command injection
			FILE *ls_file = popen(command, "r");
			if(ls_file == NULL){
				char *response_message = "Couldn't ls on ftp server\n";
				size_t message_size = strlen(response_message +1);
				response.message = malloc(message_size);
				strcpy(response.message, response_message);
				response.size = message_size;
			} else {
				//filenames can be a maaximum of 255 characters
				//assume <100 files on ftp server. TODO: validate assumption
				char filenames[255*MAX_FILES];
				size_t nread;
				size_t return_size = 0;

				do{

						nread= fread(filenames+return_size, sizeof(char), CHUNK, ls_file);
						return_size += nread;
					} while(nread == CHUNK);
				response.size=return_size+1;
				response.message = malloc(return_size) +1 ;
				memcpy(response.message, filenames, return_size);
			}
		}
		break;
		//exit command
		case 'E': {
			printf("Exit command received from client, exiting.\n");
			exit(1);
		}
		break;
		default: {
			printf("Invalid command received from client.\n");
			response.message = "Invalid command received.";
			response.size = strlen(response.message+1);
		}
	}
	return response;
}
