#include "jobs.h"
#include "termios.h"
#ifndef SFISH_HELPER
#define SFISH_HELPER

#define INITIAL_CWD_BUFF_SIZE 100
#define INITIAL_INPUT_BUFF_SIZE 100
#define PROMPT_TAIL " :: wloughlin >>"
#define PROMPT_TAIL_SIZE 16 //16
#define MAX_ANSI_SIZE 20
#define INITIAL_ARGS_SIZE 10
#define INITIAL_PROCS_SIZE 5

#define ANSI_RIGHT_ARROW "\033[C"
#define ANSI_LEFT_ARROW "\033[D"
#define ANSI_DOWN_ARROW "\033[B"

#define HELP_LIST "Did you actually think this would be useful??\n"

#define KNRM "\033[0m"
#define KRED "\033[1;31m"
#define KGRN "\033[1;32m"
#define KYEL "\033[1;33m"
#define KBLU "\033[1;34m"
#define KMAG "\033[1;35m"
#define KCYN "\033[1;36m"
#define KWHT "\033[1;37m"
#define KBWN "\033[0;33m"

#define COLOR_SIZE 7



typedef struct {
	char *input;
	char *prompt;
	char *current_working_directory;
	char *previous_working_directory;
	char *color;
	char **args;
	char **procs;
	int std_in;
	int std_out;
	short num_procs;
	short procs_size;
	short num_args;
	short cwd_size;
	short input_buf_size;
	short input_len;
	short line_len;
	short cursor_pos;
	short len_prev_lines;
	short prompt_size;
	short args_size; // size of args array
	unsigned int exited : 1;
	unsigned int tty : 1;
	unsigned int in_quotes : 1;
	group_list groups;
	group *fg_gp;

} state_information;

extern state_information *state; // Struct to hold state information



void setup(int is_tty);
void cleanup();

void set_current_working_directory();
void make_prompt();
void change_directory(char *arg);
void write_right_prompt();

void read_bytes_to_input(int fd);
void process_last_bytes(char *last);
void execute_input();
void cleanup_after_command();
int execute_builtin();
void help();
void pwd();
int tokenize_input();
void execute_program(char *name);
void add_to_array(char *arg, char ***buf, short *buf_size, short *max_size);

void new_line_in_quotes();
int cursor_bounds_check(int to_move);
int execute_ansi_command(char *cmd);
void move_cursor_left(int dis);
void move_cursor_right(int dis);
void backspacer();


/*
void str_split(sized_charp_array *ret_ptr, 
	char *str, char *delims, int num_delims);
char *strip_whitespace_outside_quotes(char *str, int str_len);
*/

void shift_buf_right_at_index(void *buf, int size, void *index, int shift_amount);
void shift_buf_left_at_index(void *buf, int size, void *index, int shift_amount);






























#endif

