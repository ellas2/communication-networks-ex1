#ifndef CLIENT_H_
#define CLIENT_H_

typedef enum {
	COURSE_LIST,
	ADD_COURSE,
	RATE_COURSE,
	GET_RATE,
	QUIT,
	INVALID
} command;

command command_from_token(char *input);

int is_port_valid(char *port_str);

int register_client();

int read_msg_from_server(char* buff, int msg_length);

unsigned int read_num_from_server();

int send_num_to_server(unsigned int length);

int send_msg_to_server(char *msg, int length);

int client_handler();

int handle_list_of_courses_command();

int handle_add_course_command(char* input_msg);

int handle_rate_course_command(char* input_msg);

int handle_get_rate_command(char* input_msg);

int is_valid_course_num(char* str);

int is_valid_rating(char* str);

#endif /*CLIENT_H_*/
