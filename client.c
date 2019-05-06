#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include "client.h"

#define DEFAULT_PORT 1337
#define MAX_HOST_LEN 253 //from wikipedia
#define MAX_UN_LEN 21
#define MAX_PASS_LEN 25
#define MAX_INPUT_LEN 1048 //1048 - max len of rate course msg

int sockfd;

int is_port_valid(char *port_str){
	int len = strlen(port_str);
	int port;
	int i; 
	//check if port_str is a valid number
	for (i = 0 ; i < len ; i++){
		if (port_str[i] > '9' || port_str[i] < '0'){
			printf("ERROR: a port should be a number\n");
			return -1;
		}
	}
	port = atoi(port_str);
	//check if port number is in port range
	if (port > 65535 || port < 0){
		printf("ERROR: a port should be a number between 0 and 65535\n");
		return -1;
	}
	return 0;
}


unsigned int read_num_from_server(){
	int num;
	int32_t c_helper;
	int bytes_to_read_c, bytes_read_c;
	char* c_string;
	c_string = (char*) &c_helper;
	bytes_to_read_c = sizeof(c_helper);
	while (bytes_to_read_c > 0) {
		if ((bytes_read_c = recv(sockfd, c_string, bytes_to_read_c, 0)) == -1){
			printf("ERROR: could not read num from server\n");
			return -1;
		}
		c_string += bytes_read_c;
		bytes_to_read_c -= bytes_read_c;
	}
	num = ntohl(c_helper);
	return num;
}

int read_msg_from_server(char* buff, int msg_length){
	int bytes_to_read_str, bytes_read_str;
	bytes_to_read_str = msg_length;
	bytes_read_str = 0;
	while(bytes_to_read_str > 0)
	{
		if ((bytes_read_str = recv(sockfd, buff, bytes_to_read_str, 0)) == -1){
			printf("ERROR: could not read message from server\n");
			return -1;
		}
		buff += bytes_read_str;
		bytes_to_read_str -= bytes_read_str;
	}
	return 0;
}

int send_num_to_server(unsigned int num){
	//printf("about to send: %d to server\n", num);
	unsigned int converted_num = htonl(num);
	if (send(sockfd, &converted_num, sizeof(converted_num), 0) == -1){
		printf("ERROR: could not send num to server\n");
		return -1;
	}
	return 0;
}

int send_msg_to_server(char *msg, int length){
	int bytes_to_send, bytes_sent;
	char* buff;
	buff = msg;
	bytes_to_send = length;
	bytes_sent = 0;
	//printf("message to send to server: %s\n", buff);
	while (bytes_to_send > 0) {
		if ((bytes_sent = send(sockfd, buff, bytes_to_send, 0)) == -1){
			printf("ERROR: could not send message to server\n");
			return -1;
		}
		bytes_to_send -= bytes_sent;
		buff += bytes_sent;
	}
	return 0;
}

int handle_list_of_courses_command(){
	char *curr_course = NULL;
	int finished_reading = 0;
	int msg_len;
	char list_of_courses_command[] = "01#";
	if (send_num_to_server(strlen(list_of_courses_command)) == -1){
		printf("ERROR: handle_list_of_courses_command - failed sending length of msg to server\n");
		return -1;
	}
	if (send_msg_to_server(list_of_courses_command, strlen(list_of_courses_command)) == -1){
		printf("ERROR: handle_list_of_courses_command - failed sending msg to server\n");
		return -1;
	}
	while (finished_reading == 0){
		msg_len = read_num_from_server();
		if (msg_len == -1){
			printf("ERROR: handle_list_of_courses_command - failed reading msg len from server\n");
			return -1;
		}
		curr_course = (char*)malloc(msg_len*sizeof(char));
		if (read_msg_from_server(curr_course, msg_len) == -1){
			printf("ERROR: handle_list_of_courses_command - failed reading msg from server\n");
			return -1;
		}
		curr_course[msg_len] = '\0';
		if (strcmp(curr_course, "###") == 0){
			finished_reading = 1;
		} else{
			printf("%s", curr_course);
		}		
		free(curr_course);
	}
	return 0;
}

int is_valid_course_num(char* str){
	int len = strlen(str);
	int course_num;
	int i; 
	//check if str is a valid number
	for (i = 0 ; i < len ; i++){
		if (str[i] > '9' || str[i] < '0'){
			return -1;
		}
	}
	course_num = atoi(str);
	//check if str number is in course range
	if (course_num > 9999 || course_num < 0){
		return -1;
	}
	return 0;
}

int handle_add_course_command(char* input_msg){
	//we have: couse_number "course_name"
	//we want: 02#course_number#course_name
	int course_num;
	char comm[MAX_INPUT_LEN];
	char comm_to_send[MAX_INPUT_LEN];
	strcpy(comm, input_msg);
	char c_name_helper[MAX_INPUT_LEN];
	strcpy(comm_to_send, "02#");
	char *token = strtok(comm, " \t\r\n");//command
	token = strtok(NULL, " \t\r\n");//course_number
	if (token == NULL || is_valid_course_num(token) == -1){
		printf("Illegal command.\n");
		return -2;
	}
	course_num = atoi(token);
	strcat(comm_to_send, token);
	strcat(comm_to_send, "#");
	strcpy(c_name_helper,input_msg);
	char *token2 = strtok(c_name_helper, "\"");
	if (token2 == NULL){
		printf("Illegal command.\n");
		return -2;
	}
	token2 = strtok(NULL, "\"");
	if (token2 == NULL){
			printf("Illegal command.\n");
			return -2;
	}
	strcat(comm_to_send, token2);
	if (send_num_to_server(strlen(comm_to_send)) == -1){
		printf("ERROR: handle_add_course_command - failed sending length of msg to server\n");
		return -1;
	}
	if (send_msg_to_server(comm_to_send, strlen(comm_to_send)) == -1){
		printf("ERROR: handle_add_course_command - failed sending msg to server\n");
		return -1;
	}
	unsigned int succ = read_num_from_server();
	if (succ == 1){
		printf("%d exists in the database!\n", course_num);
	} else if (succ == 0){
		printf("%d added successfully.\n", course_num);
	} else{
		printf("ERROR: handle_add_course_command - invalid response from server\n");
		return -1;
	}
	return 0;
}

int is_valid_rating(char* str){
	int len = strlen(str);
	int rating;
	int i; 
	//check if str is a valid number
	for (i = 0 ; i < len ; i++){
		if (str[i] > '9' || str[i] < '0'){
			return -1;
		}
	}
	rating = atoi(str);
	//check if str number is in course range
	if (rating > 100 || rating < 0){
		return -1;
	}
	return 0;
}

int handle_rate_course_command(char* input_msg){
	//we have:course_number rating_value "rating_text"
	//we want: 03#course_number#rating_value#rating_text
	char comm[MAX_INPUT_LEN];
	char comm_to_send[MAX_INPUT_LEN];
	char c_name_helper[MAX_INPUT_LEN];
	strcpy(comm, input_msg);
	strcpy(comm_to_send, "03#");
	char *token = strtok(comm, " \t\r\n");//command
	token = strtok(NULL, " \t\r\n");//course_number
	if (token == NULL || is_valid_course_num(token) == -1){
		printf("Illegal command.\n");
		return -2;
	}
	strcat(comm_to_send, token);
	strcat(comm_to_send, "#");
	token = strtok(NULL, " \t\r\n");//rating_value
	if (token == NULL || is_valid_rating(token) == -1){
		printf("Illegal command.\n");
		return -2;
	}
	strcat(comm_to_send, token);
	strcat(comm_to_send, "#");
	strcpy(c_name_helper,input_msg);
	char *token2 = strtok(c_name_helper, "\"");
	if (token2 == NULL){
		printf("Illegal command.\n");
		return -2;
	}
	token2 = strtok(NULL, "\"");
	if (token2 == NULL){
			printf("Illegal command.\n");
			return -2;
	}
	strcat(comm_to_send, token2);
	if (send_num_to_server(strlen(comm_to_send)) == -1){
		printf("ERROR: handle_rate_course_command - failed sending length of msg to server\n");
		return -1;
	}
	if (send_msg_to_server(comm_to_send, strlen(comm_to_send)) == -1){
		printf("ERROR: handle_rate_course_command - failed sending msg to server\n");
		return -1;
	}
	unsigned int succ = read_num_from_server();
	if (succ == 1){
		printf("Illegal command.\n");
		return -2;
	} else if (succ != 0){
		printf("ERROR: handle_rate_course_command - invalid response from server\n");
		return -1;
	}
	return 0;
}

int handle_get_rate_command(char* input_msg){
	char *curr_rating = NULL;
	int finished_reading = 0;
	int msg_len;
	//we have: course number
	//we want: 04#course_number
	char comm[MAX_INPUT_LEN];
	char comm_to_send[MAX_INPUT_LEN];
	strcpy(comm, input_msg);
	strcpy(comm_to_send, "04#");
	char *token = strtok(comm, " \t\r\n");//command
	token = strtok(NULL, " \t\r\n");//course_number
	if (is_valid_course_num(token) == -1){
		printf("Illegal command.\n");
		return -2;
	}
	strcat(comm_to_send, token);
	if (send_num_to_server(strlen(comm_to_send)) == -1){
		printf("ERROR: handle_get_rate_command - failed sending length of msg to server\n");
		return -1;
	}
	if (send_msg_to_server(comm_to_send, strlen(comm_to_send)) == -1){
		printf("ERROR: handle_get_rate_command - failed sending msg to server\n");
		return -1;
	}
	while (finished_reading == 0){
		msg_len = read_num_from_server();
		if (msg_len == -1){
			printf("ERROR: handle_list_of_courses_command - failed reading msg len from server\n");
			return -1;
		}
		curr_rating = (char*)malloc(msg_len*sizeof(char));
		if (read_msg_from_server(curr_rating, msg_len) == -1){
			printf("ERROR: handle_list_of_courses_command - failed reading msg from server\n");
			return -1;
		}
		curr_rating[msg_len] = '\0';
		if (strcmp(curr_rating, "###") == 0){
			finished_reading = 1;
		} else{
			printf("%s", curr_rating);
		}		
		free(curr_rating);
	}
	unsigned int succ = read_num_from_server();
		if (succ == 1){
			printf("Illegal command.\n");
			return -2;
		} else if (succ != 0){
			printf("ERROR: handle_get_rate_command - invalid response from server\n");
			return -1;
		}
	return 0;
}

command command_from_token(char *token){
	if (strcmp(token, "list_of_courses") == 0){
		return COURSE_LIST;
	} else if (strcmp(token, "add_course") == 0){
		return ADD_COURSE;
	} else if (strcmp(token, "rate_course") == 0){
		return RATE_COURSE;
	} else if (strcmp(token, "get_rate") == 0){
		return GET_RATE;
	} else if (strcmp(token, "quit") == 0){
		return QUIT;
	} 
	return INVALID;
}

int client_handler(){
	command curr_command;
	char input_msg[MAX_INPUT_LEN];
	char input_msg_cpy[MAX_INPUT_LEN];
	do{
		fgets(input_msg, MAX_INPUT_LEN, stdin);
		strcat(input_msg, "\0");
		strcpy(input_msg_cpy, input_msg);
		//read command itself
		char *token = strtok(input_msg, " \t\r\n");
		curr_command = command_from_token(token);
		if (curr_command == INVALID){
			printf("Illegal command.\n");
		} else if (curr_command == COURSE_LIST){
			if (handle_list_of_courses_command() == -1){
				return -1;
			}
		} else if (curr_command == ADD_COURSE){
			if (handle_add_course_command(input_msg_cpy) == -1){
				return -1;
			}
		} else if (curr_command == RATE_COURSE){
			if (handle_rate_course_command(input_msg_cpy) == -1){
				return -1;
			}
		} else if (curr_command == GET_RATE){
			if (handle_get_rate_command(input_msg_cpy) == -1){
				return -1;
			}
		}
	} while (curr_command != QUIT);
	return 0;
}


int register_client(){
	//get welcome message from server
	int login_successful = 0;
	int try_to_login = 1;
	char welcome_msg[24];
	char username[MAX_UN_LEN];
	char password[MAX_PASS_LEN];
	unsigned int welcome_msg_len = read_num_from_server();
	if (welcome_msg_len == -1){
		printf("ERROR: failed reading welcome msg len from server\n");
		return -1;
	}
	if (read_msg_from_server(welcome_msg, welcome_msg_len) == -1){
		printf("ERROR: failed reading welcome msg from server\n");
		return -1;
	}
	printf("%s\n", welcome_msg);
	while (login_successful == 0){
		//get username and password from user and send them to server
		fgets(username, MAX_UN_LEN, stdin);
		char *token = strtok(username, " ");
		char *un = strtok(NULL, "\n");
		if (strcmp(token, "User:") != 0 || un == NULL){
			printf("Failed to login.\n");
			try_to_login = 0;
		}
		if (try_to_login == 1){
			if (send_num_to_server(strlen(un)) == -1){
				printf("ERROR: failed sending username length to server\n");
				return -1;
			}
			if (send_msg_to_server(un, strlen(un)) == -1){
				printf("ERROR: failed sending username to server\n");
				return -1;
			}
			fgets(password, MAX_PASS_LEN, stdin);

			char *token2 = strtok(password, " ");
			char *pass = strtok(NULL, "\n");
			if (strcmp(token2, "Password:") != 0 || pass == NULL){
				printf("Failed to login.\n");
				try_to_login = 0;
			}
			if (try_to_login == 1){
				if (send_num_to_server(strlen(pass)) == -1){
					printf("ERROR: failed sending password length to server\n");
					return -1;
				}
				if (send_msg_to_server(pass, strlen(pass)) == -1){
					printf("ERROR: failed sending password to server\n");
					return -1;
				}
				int succ = read_num_from_server();
				if (succ == 1){
					printf("Failed to login.\n");
				} else if (succ == 0){
					login_successful = 1;
					printf("Hi %s, good to see you.\n", un);
				} else{
					printf("ERROR: invalid response from server\n");
					return -1;
				}
			}

		}
		try_to_login = 1;
	}
	return 0;
}


int main(int argc, char *argv[]){
	char hostname[MAX_HOST_LEN];
	int port = DEFAULT_PORT;
	char username[MAX_UN_LEN];
	char password[MAX_PASS_LEN];
	(void) password;
	(void) username;
	if (argc > 3){
		printf("ERROR: too many arguments! up to 3 can be provided.\n");
		return -1;
	} else if (argc == 1){//no hostname or port
		strcpy(hostname, "127.0.0.1");
	} else if (argc == 2 || argc == 3){
		sprintf(hostname, "%s", argv[1]);
		if (argc == 3){
			if (is_port_valid(argv[2]) == 0){
				port = atoi(argv[2]);
			} else {
				return -1;
			}
		}
	}	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1){
		printf("ERROR: failed creating socket\n");
		return -1;
	}
	struct sockaddr_in serv_addr;
	struct hostent *server;
	server = gethostbyname(hostname);
	if (server == NULL){
		printf("ERROR: could not resolve hostname\n");
		close(sockfd);
		return -1;
	}
	serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(serv_addr.sin_family, hostname, &(serv_addr.sin_addr));
   	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        printf("ERROR: failed connecting to server\n");
        return -1;
    }
    if (register_client() == -1){
    	printf("ERROR: unable to register client\n");
    	close(sockfd);
    	return -1;
    }
    if (client_handler() == -1){
    	printf("ERROR: error while handling client requests\n");
    	close(sockfd);
    	return -1;
    }
    close(sockfd);
}
