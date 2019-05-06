#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <dirent.h>
#include <signal.h>
#include <libgen.h>

#define MAX_TEXT_RATING 1124
#define MAX_CLIENTS 25
#define MAX_LEN_USER_PASS 15
#define MAX_COURSE_LEN 100

char *users_file;
char *courses_location;
int listenfd = -1;

void sig_handler(int signum)
{
  close(listenfd);
}
int sendall(int client_fd, char *buf, int len) 
{
  int send_total = 0;
  int left_to_send = len;
  int len_to_send = htonl(len);
  int sent_now = 0;
  send(client_fd, &len_to_send, sizeof(len_to_send), 0);
  while(send_total < len) 
  {
    sent_now = send(client_fd, buf+send_total, left_to_send, 0);
    if (sent_now < 0) 
    { 
      return 1;
    }
    send_total += sent_now;
    left_to_send -= sent_now;
  }
  return 0; 
}

int is_dir_empty(char *dirname) {
  int n = 0;
  struct dirent *d;
  DIR *dir = opendir(dirname);
  if (dir == NULL) //Not a directory or doesn't exist
    return 1;
  while ((d = readdir(dir)) != NULL) {
    if(++n > 2)
      break;
  }
  closedir(dir);
  if (n <= 2) //Directory Empty
    return 1;
  else
    return 0;
}


int list_all_courses(int client_fd)
{
  DIR *dir;
  struct dirent *ent;
  char course_name [MAX_COURSE_LEN];
  char line [MAX_TEXT_RATING + MAX_COURSE_LEN + 3];
  char file_path [MAX_TEXT_RATING + MAX_COURSE_LEN + 3];
  if ((dir = opendir (courses_location)) != NULL) 
  {
    while ((ent = readdir (dir)) != NULL) 
    {
      if (is_dir_empty(courses_location) == 1){
    	 sendall(client_fd, "###", strlen("###"));
    	 closedir (dir);
    	 return 1;
      }
      strcpy(file_path, courses_location);
      strcat(file_path, "/");
      strcat(file_path, ent->d_name);
      FILE *file = fopen (file_path, "r" );
      if (file == NULL)
      {
        perror (file_path);
        return 1;
      }
      if (strcmp(basename(file_path), ".") != 0 && strcmp(basename(file_path), "..") != 0){
    	  strcpy(line, basename(file_path));
      }
      strcat(line, ":\t");
      if (fgets ( course_name, sizeof (course_name), file ) != NULL)
      {
        // printf ("%s:  %s", ent->d_name, line);
    	  strcat(line, course_name);
          sendall(client_fd, line, strlen(line));
      }
      fclose(file);
    }
    sendall(client_fd, "###", strlen("###"));
    closedir (dir);
  } 
  else 
  {
    perror ("");
    return 1;
  }
  return 0;
}

int read_all_ratings(int client_fd, char* course_num)
{
  char course_path[MAX_TEXT_RATING];
  strcpy(course_path, courses_location);
  char line [MAX_TEXT_RATING + MAX_COURSE_LEN + 3];
  strcat(course_path, "/");
  strcat(course_path, course_num);
  FILE *file = fopen (course_path, "r" );
  if (file == NULL)
  {
	sendall(client_fd, "###", strlen("###"));

    //perror (course_path);//client might be trying to get rating for a non-existent course
	//printf("file is null\n");
    return 1;
  }
  fgets ( line, sizeof (line), file ); // skip name of course
  while ( fgets ( line, sizeof (line), file ) != NULL ) 
  {
    sendall(client_fd, line, strlen(line));
  }
  sendall(client_fd, "###", strlen("###"));
  fclose(file);
  return 0;
}

int append_to_file(char* course_num, char* user, char* rating, char* text) //Add rating
{
  char course_path[MAX_TEXT_RATING];
  strcpy(course_path, courses_location);
  strcat(course_path, "/");
  strcat(course_path, course_num);
  FILE *file = fopen (course_path, "r" );
  if (file == NULL)
  {
    //perror (course_path);//client might be trying to add rating for a non-existent course
    return 1;
  }
  file = fopen (course_path, "a" );
  fprintf(file, "%s:\t%s\t\"%s\"\n", user, rating, text);
  fclose(file);
  return 0;
}

int create_new_course(char* course_num, char* course_name)
{
  char course_path[MAX_TEXT_RATING];
  strcpy(course_path, courses_location);
  strcat(course_path, "/");
  strcat(course_path, course_num);
  FILE *file = fopen (course_path, "r" );
  if (file != NULL)
  {
    fclose(file);
    return 1;
  }
  file = fopen (course_path, "w" );
  if (file == NULL)
  {
     perror (courses_location);
     return 2;
  }
  fprintf(file, "\"%s\"\n", course_name);
  fclose(file);
  return 0;
}

int check_username_password(char* username, char* password)
{ 
  char curr_user[MAX_LEN_USER_PASS];
  char curr_pass[MAX_LEN_USER_PASS];
  (void)curr_pass;
  (void)curr_user;
  char delim[] = "\t\n";
  char *split_str;
  int cmp_user, cmp_pass;
  FILE *file = fopen (users_file, "r" );
  if (file != NULL)
  {
    char line [MAX_LEN_USER_PASS*2 + 10];
    while ( fgets ( line, sizeof (line), file ) != NULL ) 
    {
      split_str = strtok(line, delim);
      cmp_user = strcmp(username, split_str);
      split_str = strtok(NULL, delim);
      cmp_pass = strcmp(password, split_str);
      if (cmp_user == 0 && cmp_pass == 0)
      {
        fclose(file);
        return 0;
      }
    }
    fclose(file);
  }
  else
  {
     perror (users_file);
     return 2;
  }
  return 1;
}

int handle_msg(int client_fd, char* user, char* buff, int msg_size)
{
  char delim[] = "_#";
  char msg[MAX_TEXT_RATING*2];
  strcpy(msg, buff);
  char *split_str;
  int ret_value = 0;
  split_str = strtok(msg, delim);
  if (split_str == NULL)
    return 1;

  if (strcmp(split_str, "01") == 0) //List all courses in DB
  {
    list_all_courses(client_fd);
  }

  else if (strcmp(split_str, "02") == 0) //Add new course
  {
    split_str = strtok(NULL, delim);
    if (split_str == NULL)
      return 1;
    char new_course_id[MAX_COURSE_LEN];
    strcpy(new_course_id, split_str);
    split_str = strtok(NULL, delim);
    if (split_str == NULL)
      return 1;
    ret_value = create_new_course(new_course_id, split_str);
    unsigned int to_send = htonl(ret_value);
    int msg_sent = send(client_fd, &to_send, sizeof(to_send), 0);
    if (msg_sent < 0)
    {
        printf("Failed to write to client: %s", strerror(errno));
        return 1;
    }
  }

  else if (strcmp(split_str, "03") == 0) //Add new rating to course
  {
    split_str = strtok(NULL, delim);
    if (split_str == NULL)
      return 1;
    char course_id[MAX_COURSE_LEN];
    strcpy(course_id, split_str);
    split_str = strtok(NULL, delim);
    if (split_str == NULL)
      return 1;
    char course_rate[MAX_COURSE_LEN];
    strcpy(course_rate, split_str);
    split_str = strtok(NULL, delim);
    if (split_str == NULL)
      return 1;
    ret_value = append_to_file(course_id, user, course_rate, split_str);
    unsigned int to_send = htonl(ret_value);
    int msg_sent = send(client_fd, &to_send, sizeof(to_send), 0);
    if (msg_sent < 0)
    {
        printf("Failed to write to client: %s", strerror(errno));
        return 1;
    }
  }
  else if (strcmp(split_str, "04") == 0) //Read all ratings of a specific course
  {
    split_str = strtok(NULL, delim);
    if (split_str == NULL)
      return 1;
    ret_value = read_all_ratings(client_fd, split_str);
    //printf("ret_value: %d", ret_value);
    unsigned int to_send = htonl(ret_value);
	int msg_sent = send(client_fd, &to_send, sizeof(to_send), 0);
	if (msg_sent < 0)
	{
		printf("Failed to write to client: %s", strerror(errno));
		return 1;
	}
  }
  return 0;
}

int receive_msg(int client_fd, char* buff, int *msg_size_ret)
{
	unsigned int msg_size;
	int recv_status;
	recv_status = recv(client_fd, &msg_size, sizeof(msg_size), 0);
	if (recv_status == 0)
	{
		return 1;
	}
	else if (recv_status < 0)
	{
		return 1;
	}
  	msg_size = ntohl(msg_size);
	*msg_size_ret = msg_size;
	int bytes_to_read_str, bytes_read_str;
	bytes_to_read_str = msg_size;
	bytes_read_str = 0;
	while(bytes_to_read_str > 0)
	{
		if ((bytes_read_str = recv(client_fd, buff, bytes_to_read_str, 0)) == -1){
			printf("Failed to read msg from client\n");
			return -1;
		}
		buff += bytes_read_str;
		bytes_to_read_str -= bytes_read_str;
	}
	buff[bytes_read_str] = '\0';

  return 0;
}

int handle_client(int client_fd)
{
  int msg_size;
  unsigned int user_pass_ok = 1;
  char msg[MAX_TEXT_RATING];
  char username[MAX_LEN_USER_PASS];
  char password[MAX_LEN_USER_PASS];
  char *welcome = "Welcome! Please log in.";
  sendall(client_fd, welcome, strlen(welcome));
  while (user_pass_ok != 0)
  {
    if (receive_msg(client_fd, username, &msg_size)) //Get username
    {
      return 1;
    }
    username[msg_size] = '\0';
    if (receive_msg(client_fd, password, &msg_size)) //Get password
    {
      return 1;
    }
    password[msg_size] = '\0';
    user_pass_ok = check_username_password(username, password); //0 if ok, 1 if incorrect
    unsigned int to_send = htonl(user_pass_ok);
    int msg_sent = send(client_fd, &to_send, sizeof(to_send), 0);
    if (msg_sent < 0)
    {
        printf("Failed to write to client: %s", strerror(errno));
        return 1;
    }
  }

  while (1) //Receive commands until disconnected
  {
    if (receive_msg(client_fd, msg, &msg_size))
      return 0;
    msg[msg_size] = '\0';
    //printf("msg read from client: %s\n", msg);
    int ret_status = handle_msg(client_fd, username, msg, msg_size);
    if (ret_status != 0)
    {
      return 1;
    }
  }
}

int main(int argc, char *argv[])
{
  unsigned short port_num = 1337;
  if (argc == 4)
  {
    port_num = atoi(argv[3]);
  }
  else if (argc != 3)
  {
    printf("Usage: please provide 2 or 3 arguments - port number\n");
  }
  if (signal(SIGINT, sig_handler) == SIG_ERR) //Register SIGINT
  {
    perror("Error while installing a signal handler.\n");
    exit(1);
  }
  int connfd = -1;
  int recv_status;
  (void)recv_status;

  users_file = argv[1];
  courses_location = argv[2];
  // handle_msg(1234, "Bob", "02#111#logic" ,5);
  // handle_msg(1234, "Bob", "02#222#infi", 5);
  // handle_msg(1234, "Bob", "03#222#87#not so good", 5);
  // handle_msg(1234, "Alice", "03#222#70#almost bad", 5);
  // handle_msg(1234, "Bob", "03#111#80#itsok", 5);
  // handle_msg(1234, "Bob", "04#222", 5);
  listenfd = socket( AF_INET, SOCK_STREAM, 0 );
  if (listenfd < 0)
  {
    perror("Failed to create socket");
    exit(1);
  }

  struct sockaddr_in serv_addr, client_addr;
  memset( &serv_addr, 0, sizeof(serv_addr) );
  socklen_t addrsize = sizeof(struct sockaddr_in );
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(port_num);

  if( 0 != bind( listenfd, (struct sockaddr*) &serv_addr, addrsize ) )
  {
    printf("\n Error : Bind Failed. %s \n", strerror(errno));
    return 1;
  }
  if( 0 != listen( listenfd, MAX_CLIENTS) )
  {
    printf("\n Error : Listen Failed. %s \n", strerror(errno));
    return 1;
  }
  while( 1 ) //Keep listening for new clients
  {
    connfd = accept( listenfd, (struct sockaddr*)&client_addr, &addrsize);
    if( connfd < 0 )
    {
      printf("\n Error : Accept Failed. %s\n", strerror(errno));
      return 1;
    }
    int flag = 0;
    (void)flag;
    handle_client(connfd);
    close(connfd);
  }
}
