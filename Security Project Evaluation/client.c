// FTP Client
// Group 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define CHUNK 1440

int cmd_helper(char* cmd);
int get_fname(char* cmd, char** fname);
int get_path(char* path, char* fname, char** totalpath, int check_exists);
void recv_response(int* sock, char** response_buffer, int* rec_len);
int get_fhash(char *fname, char** hash_fname);
int checkHash(char *message, int size);
void sha256_to_string(unsigned char hash[SHA256_DIGEST_LENGTH], char out[65]);

int main(int argc, char *argv[]){
  /*The FTP client takes a port, ip, and the directory from which it reads and writes.*/
  struct sockaddr_in server;
  int sock, connection, len, rec_len;
  int32_t size;
  char cmd[100], buff[CHUNK];
  char* path;
  char* fname;
  char* fname_hash;
  char* totalpath_hash;
  char* totalpath;
  char* cmd_type;
  char* response_buffer;

  if(argc != 4){
    printf("Wrong number of parameters.\nThe FTP client takes a port, ip, and the directory from which it reads and writes.\n");
    exit(1);
  }

  if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
    printf("Socket creation failed.\n");
    exit(1);
  }
  server.sin_family = AF_INET;
  int port_var = atoi(argv[1]);
  if(port_var < 1)
  {
    printf("Port number invalid.\n");
    exit(1);
  }
  server.sin_port = htons(port_var);
  server.sin_addr.s_addr = inet_addr(argv[2]);
  if(server.sin_addr.s_addr == -1 && strcmp(argv[2], "255.255.255.255") != 0)
  {
    printf("IP invalid, must be valid IPv4 address in byte dot notation.\n");
    exit(1);
  }
  if((connection = connect(sock,(struct sockaddr*)&server, sizeof(server))) == -1){
    printf("Connection failed.\n");
    exit(1);
  }

  struct stat sb;
  if(!(stat(argv[3], &sb) == 0 && S_ISDIR(sb.st_mode))){
    printf("Error: Directory provided [%s] does not exist.\n", argv[3]);
    exit(1);
  }

  len = strlen(argv[3]);
  if (argv[3][len-1] != '/'){
    path = (char *) calloc(len+2, sizeof(char));
    strncpy(path, argv[3], len);
    path[len] = '/';
  } else {
    path = argv[3];
  }

  printf("Client Path: {%s}\n", path);

  printf("Ready to accept commands: \n\t'put <filename> - will upload a file\n\t'get <filename>'' - will get a file\n\t'ls' - lists the files on the FTP server\n\t'exit' - quit the FTP client");
  //Start accepting, parcing and executing commands
  while(1){
    printf("\n->");
    fflush(stdin);
    fgets(cmd, 100, stdin);
    switch(cmd_helper(cmd)){
      case(0):
        printf("Put cmd.\n");
        cmd_type = "P ";
        if (get_fname(cmd, &fname)==-1){
          free(fname);
          break;
        } else if (get_path(path, fname, &totalpath, 1)==-1){
          free(totalpath);
          break;
        }
        //Verify hash file
        if (get_fhash(fname, &fname_hash) ==-1) {
          printf("Error: a file of <filename>_hash must exist when transmitting files");
          free(fname_hash);
          free(fname);
          free(totalpath);
          break;
        } else if(get_path(path, fname_hash, &totalpath_hash, 1) == -1){
          free(fname_hash);
          free(fname);
          free(totalpath);
          free(totalpath_hash);
          break;
        }
        // Read in the hash from the file
        FILE *hash_file;
        hash_file = fopen(totalpath_hash, "rb");
        char hash_buff[65];
        fread(hash_buff, 1, 64, hash_file);

        stat(totalpath, &sb);
        // Size here is the overall size of the message sent to the ids.  Of format <char type of command><string filename><EOF delimited file>
        size = htonl(strlen(cmd_type)+(strlen(fname)+1)+sb.st_size + 64);
        send(sock, &size, sizeof(int32_t), 0);
        send(sock, cmd_type, strlen(cmd_type), 0);
        send(sock, fname, strlen(fname)+1, 0);
        send(sock, hash_buff, 64, 0);

        FILE *fp;
        fp = fopen(totalpath, "rb");
        size_t nread;
        while((nread = fread(buff, 1, CHUNK, fp)) > 0){
          send(sock, buff, nread, 0);
        }
        fclose(fp);
        free(fname);
        free(totalpath);

        recv_response(&sock, &response_buffer, &rec_len);
        printf("Response: %s\n", (response_buffer));
        free(response_buffer);
        break;

      case(1):
        printf("Get cmd.\n");
        cmd_type = "G ";
        if (get_fname(cmd, &fname)==-1){
          free(fname);
          break;
        } else if(get_path(path, fname, &totalpath, 0) == -1){
          free(totalpath);
          break;
        }
        size = htonl(strlen(cmd_type)+strlen(fname)+1);
        send(sock, &size, sizeof(int32_t), 0);
        send(sock, cmd_type, strlen(cmd_type), 0);
        send(sock, fname, strlen(fname)+1, 0);
        free(fname);

        recv_response(&sock, &response_buffer, &rec_len);
        if(checkHash(response_buffer, rec_len) <0){
          free(response_buffer);
          printf("%s has an incorrect or missing hash value\n", fname );
          break;
        }
        FILE *out_file;
        out_file = fopen(totalpath, "wb");

        size_t nwrite;
        printf("Receive len: %d\n", rec_len);
        for(nwrite =0; nwrite <rec_len-64;
          (nwrite+= fwrite(response_buffer+nwrite+64, sizeof(char), rec_len-64, out_file)));
        fclose(out_file);
        printf("Response: %s\n", (response_buffer));
        free(response_buffer);
        break;

      case(2):
        printf("LS cmd.\n");
        cmd_type = "L";
        size = htonl(strlen(cmd_type));
        send(sock, &size, sizeof(int32_t), 0);
        send(sock, cmd_type, strlen(cmd_type), 0);

        recv_response(&sock, &response_buffer, &rec_len);
        printf("Response: %s\n", (response_buffer));
        free(response_buffer);
        break;

      case(3):
        printf("Exit cmd.\n");
        cmd_type = "E";
        size = htonl(strlen(cmd_type));
        send(sock, &size, sizeof(int32_t), 0);
        send(sock, cmd_type, strlen(cmd_type), 0);

        exit(1);
      case(-1):
        printf("Error: Command not recognized.\n");
        printf("Accepted commands are: \n\t'put <filename> - will upload a file\n\t'get <filename>'' - will get a file\n\t'ls' - lists the files on the FTP server\n\t'exit' - quit the FTP client");
        break;
    }
  }
}


void recv_response(int* sock, char** response_buffer, int* rec_len){
  /* Helper: Handles the response from server. */
  int size;
  int size_holder = 0;
  int exp_size;
  int32_t net_size;
  char buffer[CHUNK];
  char *len_buffer = (char *)&net_size;
  memset(len_buffer, 0, sizeof(int32_t));

  printf("WAITING FOR RESPONSE:\n");
  recv(*sock, len_buffer, sizeof(int32_t), 0);
  *rec_len = ntohl(net_size);
  *response_buffer = (char *) calloc(*rec_len + 1, sizeof(char));
  memset(*response_buffer, '\0', *rec_len+1);
  while(size_holder < *rec_len)
  {
    memset(buffer, 0, sizeof(buffer));
    exp_size = ((*rec_len-size_holder) < CHUNK) ? (*rec_len-size_holder): CHUNK;
    size = recv(*sock, buffer, exp_size, 0);
    if (size <= 0){
      printf("READ 0 bytes trasmission ended.\n");
      break;
    }
    memcpy((*response_buffer+size_holder), buffer, size);
    size_holder += size;
  }
  printf("Recieved a total length of: %d, which was written to 'response_buffer'\n", *rec_len);
}


// Takes first 64 bytes as hash and verifies it with the rest of the file
int checkHash(char *message, int size){
  //Get the hash of the file
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  char file[size-64];
  char hash_string[65];
  memcpy(file, message+64, size-64);
  SHA256_Update(&sha256, file, size-64);
  SHA256_Final(hash, &sha256);
  sha256_to_string(hash, hash_string);
  // Compare the calculated hash with the sent one
  char message_hash[65];
  strncpy(message_hash, message, 64);
  message_hash[64] = 0;
  if(strncmp(message, hash_string, 64) != 0){
    return -1;
  }
  return 1;


}

//Helper function to convert hash to string
void sha256_to_string(unsigned char hash[SHA256_DIGEST_LENGTH], char out[65]){
  int i =0;
  for(i =0; i< SHA256_DIGEST_LENGTH; i++){
    sprintf(out+(i*2), "%02x", hash[i]);
  }
  out[64] = 0;
}

int get_fname(char* cmd, char** fname){
  /* Helper: Gets the file name and makes sure it is not a directory */
  int len = strlen(cmd);
  *fname = calloc((len-5)+1, sizeof(char));
  strncpy(*fname, cmd+4, len-5);
  if (strchr(*fname, '/')){
    printf("Error: File name cannot be a path or contain any '/'s. ");
    return -1;
  }
  return 1;
}

// Assume hash files are stored in <filename>_hash
int get_fhash(char *fname, char** hash_fname){
  int len =strlen(fname);
  *hash_fname = calloc((len+5)+1, sizeof(char));
  strncpy(*hash_fname, fname, len);
  strncat(*hash_fname, "_hash", 5);
  if (strchr(*hash_fname, '/')){
    printf("Error: File name cannot be a path or contain any '/'s.\n ");
    return -1;
  }
  return 1;
}

int get_path(char* path, char* fname, char** totalpath, int check_exists){
  /* Helper: Gets the total path of the file and verifies that its a.) Not a Directory,
  b.) it exists. */
  int len = strlen(path)+strlen(fname);
  *totalpath = (char *) calloc(len+1, sizeof(char));
  strncpy(*totalpath, path, strlen(path));
  strcat(*totalpath, fname);
  if(check_exists){
    struct stat sb;
    if (!(stat(*totalpath, &sb) == 0 && !S_ISDIR(sb.st_mode))){
      printf("Error: File provided [%s] is not located with in the current working directory [%s].\n", fname, path);
      return -1;
    }
  }
  return 1;
}

int cmd_helper(char* cmd){
  /* Helper: Gets command type, and returns coresponding int for switch
   cases. */
  if (strncmp(cmd, "put ", 4)==0){
    return 0;
  }
  else if (strncmp(cmd, "get ", 4)==0){
    return 1;
  }
  else if (strncmp(cmd, "ls", 2)==0){
    return 2;
  }
  else if (strncmp(cmd, "exit", 4)==0){
    return 3;
  }
  return -1;
}
