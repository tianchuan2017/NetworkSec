// Utils
// Group 1

#ifndef TRANSPORT_FOR_IDS
#define TRANSPORT_FOR_IDS

#define CHUNK 1440
#define MAX_FILES 100
typedef struct
{
	int32_t size;
	char *message;
} transport;

void ErrorOut(char *msg);

transport FTPExecute(transport input, char *ftp_dir);

void IDSHandler(int client_socket, transport ids_signatures[], char * ftp_dir, char *ids_logname, char* ip);

int get_fhash(char *fname, char** hash_fname);

#endif
