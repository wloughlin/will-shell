#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <termios.h>
#include "will_shell_helper.h"
#include "jobs.h"
#include "will_shell.h"
#include "debug.h"
#include "wrappers.h"


state_information *state;

struct termios old_term_settings;


void foreground(group *fg_group) {
	
	struct termios prev_term_settings;
	tcgetattr(STDIN_FILENO, &prev_term_settings);
	tcsetattr(STDIN_FILENO, TCSADRAIN, &old_term_settings);
	tcsetpgrp(STDIN_FILENO, fg_group->pgid);


	sigset_t mask_nchild, prev;
	sigfillset(&mask_nchild);
	sigdelset(&mask_nchild, SIGCHLD);
	sigprocmask(SIG_SETMASK, &mask_nchild, &prev);

	killpg(fg_group->pgid, SIGCONT);

	state->fg_gp = fg_group;
	
	while (state->fg_gp != NULL) {

		sigsuspend(&mask_nchild);
		if(state->fg_gp != NULL && !list_has_pgid(&(state->groups),
			state->fg_gp->pgid)) {
			state->fg_gp = NULL;
			//close(infile);
		}
	}
	tcsetattr(STDIN_FILENO, TCSANOW, &prev_term_settings);
	tcsetpgrp(STDIN_FILENO, getpgid(getpid()));
	sigprocmask(SIG_SETMASK, &prev, NULL);
}

void print_jobs()
{
	group *current = state->groups.head;
	while(current != NULL) {
		printf(JOBS_LIST_ITEM, current->jid, current->name);
		current = current->next;
	}
}

void child_handler(int sig)
{
	int old_errno = errno;
	errno = 0; 
	int status;
	sigset_t maskall, maskprev;
	pid_t pid;
	sigfillset(&maskall);
	while((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
		sigprocmask(SIG_BLOCK, &maskall, &maskprev);
		if(WIFSTOPPED(status)) 
			state->fg_gp = NULL;
		else {
			delete_job_by_pid(&(state->groups), pid);
		}
		sigprocmask(SIG_SETMASK, &maskprev, NULL);
	}
	errno = old_errno;
}

void int_handler(int sig)
{
	int old_errno = errno;
	sigset_t maskall, maskprev;
	sigfillset(&maskall);
	if(state->fg_gp != NULL) {
		sigprocmask(SIG_BLOCK, &maskall, &maskprev);
		killpg(state->fg_gp->pgid, SIGINT);
		sigprocmask(SIG_SETMASK, &maskprev, NULL);	
	}
	errno = old_errno;
}


/*
	Called once on start
	Setup variables that will be repeatedly used during shell's operation
*/
void setup(int is_tty)
{
	setpgid(getpid(), getpid());

	sigset_t maskprev, ttou;
	sigemptyset(&ttou);
	sigaddset(&ttou, SIGTTOU);
	sigprocmask(SIG_BLOCK, &ttou, &maskprev);
	tcsetpgrp(STDIN_FILENO, getpgid(getpid()));
	sigprocmask(SIG_SETMASK, &maskprev, NULL);


	struct termios t;
	tcgetattr(STDIN_FILENO, &t);
	tcgetattr(STDIN_FILENO, &old_term_settings);
	t.c_iflag &= IGNBRK;
	t.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
	

	signal(SIGCHLD, child_handler);
	//signal(SIGSTOP, stop_handler);
	signal(SIGINT, int_handler);

	state = w_calloc(1, sizeof(state_information));
	state->prompt = NULL;

	state->procs = w_calloc(INITIAL_PROCS_SIZE, sizeof(char *));
	state->procs_size = INITIAL_PROCS_SIZE;

	state->args = w_calloc(INITIAL_ARGS_SIZE, sizeof(char *));
	state->args_size = INITIAL_ARGS_SIZE;

	state->input = w_calloc(INITIAL_INPUT_BUFF_SIZE, 1);
	state->input_buf_size = INITIAL_INPUT_BUFF_SIZE;

	state->std_out = STDOUT_FILENO;
	state->color = KNRM;
	state->tty = is_tty;

	set_current_working_directory();
	make_prompt();
}

/*
	Free allocated memory. To be called once on exit
*/ 
void cleanup(int is_child)
{
	if(!is_child)
		tcsetattr(STDIN_FILENO, TCSANOW, &old_term_settings);

	close(state->std_in);
	close(state->std_out);
	free(state->previous_working_directory);
	free(state->prompt);
	free(state->current_working_directory);
	free(state->input);
	free(state->procs);
	free(state->args);
	free((void *)state);
}


void set_current_working_directory()
{
	
	if(state->previous_working_directory != NULL)
		free(state->previous_working_directory);
	state->previous_working_directory = state->current_working_directory;
	int buf_size = INITIAL_CWD_BUFF_SIZE;
	char *buffer = w_calloc(buf_size, 1);
	while(getcwd(buffer, buf_size) == NULL && errno == ERANGE) {
		buf_size *= 2;
		buffer = realloc(buffer, buf_size);
		errno = 0;
	}
	state->current_working_directory = buffer;
	state->cwd_size = buf_size;
}




void make_prompt()
{
	if(state->tty) {
		state->prompt = w_calloc(sizeof(char), 1);
		state->prompt_size = 0;
	}
	else {
		char *home_dir;
		char *buf = NULL;
		if((home_dir = getenv("HOME"))== NULL) {
			//printf("HOME variable is NULL");
			return;
		}
		char *cw_dir = state->current_working_directory;
		int len_home = strlen(home_dir);
		int len_cwd = strlen(cw_dir);
		if(state->prompt != NULL) {
				free(state->prompt);
			}
		if(!strncmp(home_dir, cw_dir, len_home)) {
			if(strlen(cw_dir) == len_home) {
				buf = w_calloc(len_home + PROMPT_TAIL_SIZE + 1 + (2*COLOR_SIZE), 1);
				sprintf(buf, "%s%s%s%s", state->color, home_dir, PROMPT_TAIL, KNRM);
			}
			else {
				buf = w_calloc(len_cwd - len_home + 2 + PROMPT_TAIL_SIZE + 1 + (2*COLOR_SIZE), 1);
				sprintf(buf, "%s~%s%s%s", state->color, cw_dir+len_home, PROMPT_TAIL, KNRM);
			}
		}
		else {
			buf = w_calloc(len_cwd+PROMPT_TAIL_SIZE+2 + (2*COLOR_SIZE), 1);
			sprintf(buf, "%s%s%s%s", state->color, cw_dir, PROMPT_TAIL, KNRM);
		}
		state->prompt_size = strlen(buf);
		state->prompt = buf;
	}
}

void read_bytes_to_input(int fd)
{
	char buf[MAX_ANSI_SIZE+1];
	int to_read = MAX_ANSI_SIZE;
	if(state->tty)
		to_read = 1;
	int nbytes = read(STDIN_FILENO, buf, to_read);//MAX_ANSI_SIZE);
    if(nbytes <= 0) 
        return;
    *(buf+nbytes) = 0;
    process_last_bytes(buf);
}

/*
	Carrys out the commands based on bytes recieved. 
	returns 0 if input needs to be updated, 1 otherwise

*/
void process_last_bytes(char *last_bytes)
{
	if(execute_ansi_command(last_bytes))
		return;
	else if((*last_bytes == '\n' || *last_bytes == '\r') && state->in_quotes == 0) {
		execute_input();
		return;
	}
	else if(*last_bytes == '\t') {
		return;
	}
	else if(*last_bytes == 8 || *last_bytes == 127) {
		backspacer();
		return;
	}
	else {
		if(*last_bytes == '"')
			state->in_quotes = ~state->in_quotes;

		int len = strlen(last_bytes);
		if(*last_bytes != '\n' && *last_bytes != '\r') {
			char *print_index = state->input + state->len_prev_lines + 
				state->cursor_pos;
	    	if(state->line_len != state->cursor_pos)
	    		shift_buf_right_at_index(state->input, state->input_buf_size, 
	    			print_index, len);
    	}
    	else {
			new_line_in_quotes();
			return;
    	}
    	memcpy(state->input + state->len_prev_lines + state->cursor_pos,
    		last_bytes, len);

    	state->input_len += len;
    	state->line_len += len;
    	
    	if(state->input_len + MAX_ANSI_SIZE >= state->input_buf_size) {
    		state->input_buf_size *= 2;
    		state->input = w_realloc(state->input, state->input_buf_size);
    	}
    	if(!state->tty)
			w_write(STDOUT_FILENO, state->input + state->len_prev_lines +
				state->cursor_pos, state->line_len - state->cursor_pos);
		state->cursor_pos += len;
		move_cursor_left(state->line_len - state->cursor_pos);

	}

}

void new_line_in_quotes()
{
	if(state->input_len + 2 >= state->input_buf_size) {
    	state->input_buf_size *= 2;
    	state->input = w_realloc(state->input, state->input_buf_size);
    }
    state->input[state->input_len] = '\n';
    state->input[state->input_len+1] = 0;

    state->len_prev_lines += state->line_len + 1;
    state->input_len++;
    state->cursor_pos = 0;
    state->line_len = 0;

    state->prompt[0] = '>';
    state->prompt[1] = 0;

    if(!state->tty) {
    	printf("\n%s", state->prompt);
    	fflush(stdout);
    }

}

int count_char(char *str, char c)
{
	int ret = 0;
	while(str[0] != 0) {
		if(str[0] == c)
			ret++;
		str = str + 1;
	}
	return ret;
}

int check_redirect_syntax(char *str)
{
	int seen_pipe = 0;
	int seen_out = 0;
	int seen_in = 0;
	while(*str != 0) {
		if(*str == '<') {
			if(seen_pipe == 1)
				return 1;
			seen_in++;
		}
		else if(*str == '|') {
			if(seen_out)
				return 1;
			seen_pipe = 1;
		}
		else if(*str == '>')
			seen_out++;
		str = str + 1;
	}
	if(seen_in > 1 || seen_out > 1)
		return 1;
	return 0;
}

int separate_proccesses(char *buf)
{
	if(check_redirect_syntax(buf)) {
		if(!state->tty)
			putchar('\n');
		printf(SYNTAX_ERROR, "Invalid redirect");
		return -1;
	}
	char *tok = strtok(buf, "|");
	while(tok != NULL) {
		add_to_array(tok, &(state->procs), &(state->num_procs), &(state->procs_size));
		tok = strtok(NULL, "|");
	}
	add_to_array(NULL, &(state->procs), &(state->num_procs), &(state->procs_size));
	return 0;
}

void strip_leading_spaces(char *buf, int buf_size)
{
	int i = 0;
	while(buf[i] == ' ') 
		i++;
	if(i > 0)
		shift_buf_left_at_index(buf, buf_size, buf, i);
	state->input_len -= i;
}

int parse_for_redirects(char *str)
{
	state->std_in = STDIN_FILENO;
	state->std_out = STDOUT_FILENO;
	while(str != NULL && str[0] != 0) {
		if(str[0] == '<') {
			str[0] = 0;
			char *infile_name = strtok(str+1, "\" ");
			strtok(infile_name, ">");
			str = strtok(NULL, ">");
			if((state->std_in = open(infile_name, O_RDONLY)) < 0) {
				if(!state->tty)
					putchar('\n');
				printf(EXEC_ERROR, "file error");
				return -1;
			}
			if(str == NULL)
				return 0;
			else if((state->std_out = open(str, O_CREAT | O_TRUNC | O_RDWR,
				0664)) < 0) {
				if(!state->tty)
					putchar('\n');
				printf(EXEC_ERROR, "file error");
				return -1;
			}
			return 0;
		}
		else if(str[0] == '>') {
			str[0] = 0;
			char *outfile_name = strtok(str+1, "\" ");
			strtok(outfile_name, "<");
			str = strtok(NULL, "<");
			if((state->std_out = open(outfile_name, O_CREAT | O_TRUNC | O_RDWR,
				0664)) < 0) {
				if(!state->tty)
					putchar('\n');
				printf(EXEC_ERROR, "file error");
				return -1;
			}
			if(str == NULL)
				return 0;
			else if((state->std_in = open(str, O_RDONLY)) < 0) {
				if(!state->tty)
					putchar('\n');
				printf(EXEC_ERROR, "file error");
				return -1;
			}
			return 0;
		}
		else
			str = str + 1;
	}
	return 0;
}

int ischar(char c, char *test)
{
	char *str = test;
	while(*str != 0) {
		if(*str == c)
			return 1;
		str = str + 1;
	}
	return 0;
}

int tokenize_input(char *str)
{
	char in_quotes = 0;
	if(str[0] != '"' && !ischar(str[0], " \t"))
	{
		add_to_array(str, &(state->args), &(state->num_args), &(state->args_size));
	}
	while(*str != 0) {
		if(in_quotes) {
		}
		else if(ischar(str[0], " \t") && str[1] == '"') {
			str[0] = 0;
		}
		else if(ischar(str[0], " \t") && !ischar(str[1], " \t") && str[1] != 0 && !in_quotes) {
			str[0] = 0;
			if(str[1] == '>' || str[1] == '<') {
				if(parse_for_redirects(str+1) < 0)
					return -1;
				break;
			}
			add_to_array(str+1, &(state->args), &(state->num_args), &(state->args_size));
		}
		else if(str[0] == '>' || str[0] == '<') {
			if(parse_for_redirects(str) < 0)
				return -1;
			break;
		}
		else if(ischar(str[0], " \t")) {
			str[0] = 0;
		}
		if(str[0] == '"') {
			str[0] = 0;
			if(in_quotes) {
				in_quotes = 0;
				if(!ischar(str[1], " \t") && str[1] != 0) {
					add_to_array(str+1, &(state->args), &(state->num_args), &(state->args_size));
				}
			}
			else {
				in_quotes = 1;
				add_to_array(str+1, &(state->args), &(state->num_args), &(state->args_size));
			}
		}
		str = str + 1;
	}
	add_to_array(NULL, &(state->args), &(state->num_args), &(state->args_size));
	return 0;
}

void add_to_array(char *arg, char ***buf, short *buf_size, short *max_size)
{
	if(*buf_size + 1 == *max_size) {
		*max_size *= 2;
		*buf = w_realloc(*buf, sizeof(char **) * (*max_size));
	}
	(*buf)[*buf_size] = arg;
	if(arg != NULL)
		(*buf_size)++;
}

int execute_ansi_command(char *cmd)
{
	if(*cmd != '\033') // Not ansi excape.
		return 0; 
	if(!strcmp(cmd, ANSI_RIGHT_ARROW)) {
		if(cursor_bounds_check(1)) {
			move_cursor_right(1);
			state->cursor_pos += 1;
		}
		return 1;
	}
	if(!strcmp(cmd, ANSI_LEFT_ARROW)) {
		if(cursor_bounds_check(-1)) {
			move_cursor_left(1);
			state->cursor_pos -= 1;
		}
		return 1;
	}
	return 1;
	
}

int cursor_bounds_check(int to_move)
{
	int new_cursor_pos = state->cursor_pos + to_move;
	if(new_cursor_pos >= 0 && new_cursor_pos <= state->line_len) {
		return 1;
	}
	return 0;
}

void shift_buf_left_at_index(void *buf, int size, void *index, int shift_amount)
{
	while(index < buf + size - shift_amount) {
		*(char *)index = *(char *)(index + shift_amount);
		index = index + 1;
	}
	for(int i = 0; i < shift_amount; i++) {
		*(char *)(buf + size - (shift_amount + i)) = 0;
	}
}

// shifts everything from index over by shift amount
void shift_buf_right_at_index(void *buf, int size, void *index, int shift_amount)
{
	void *end = buf + size - 1;
	while(end >= index + shift_amount) {
		*(char *)end = *(char *)(end - shift_amount);
		end = end - 1;
	}
}

void move_cursor_left(int dis)
{
	if(!dis)
		return;
	printf("\033[%iD", dis);
	fflush(stdout);
}

void move_cursor_right(int dis)
{
	if(!dis)
		return;
	printf("\033[%iC", dis);
	fflush(stdout);
}

void write_right_prompt()
{
	char str[20];
	time_t t;
	time(&t);

	struct tm *local_time = localtime(&t);
	strftime(str, 20, STRFTIME_RPRMT, local_time);
	printf("\0337");
	printf("\033[%iC", 99999999);
	printf("\033[%iD", 18);
	printf("%s", str);
	
	printf("\0338");
}

void backspacer()
{
	if(cursor_bounds_check(-1)) {
		move_cursor_left(1);
		if(*(state->input + state->len_prev_lines + state->cursor_pos - 1) == '"')
			state->in_quotes = ~state->in_quotes;
		shift_buf_left_at_index(state->input, state->input_buf_size,
			state->input + state->len_prev_lines + state->cursor_pos - 1, 1);
		*(state->input + state->len_prev_lines + state->line_len - 1) = ' ';
		state->cursor_pos -= 1;
		w_write(STDOUT_FILENO, state->input + state->len_prev_lines + state->cursor_pos, 
			state->line_len - state->cursor_pos);
		fflush(stdout);
		move_cursor_left(state->line_len - state->cursor_pos);
		*(state->input + state->input_len) = 0;
		state->input_len--;
		state->line_len--;
	}
}

void execute_input()
{
	strip_leading_spaces(state->input, state->input_buf_size);

	if(state->input_len == 0) {
		if(!state->tty)
			putchar('\n');
		cleanup_after_command();
		return;
	}
	char *name = w_calloc(state->input_len+1, 1);
	memcpy(name, state->input, state->input_len);
	if(separate_proccesses(state->input) < 0) {
		cleanup_after_command();
		return;
	}
	if(state->num_procs == 1) {
		strtok(name, " ");
	}
	if(!tokenize_input(state->procs[0])){
		if(!execute_builtin())
			execute_program(name);
		else 
			free(name);
	}
	if(!state->exited)
		cleanup_after_command();
}

char **get_args_section(char ***remaining_args)
{
	char **input = *remaining_args;
	int inc = 0;
	while(input[inc] != NULL && strncmp(input[inc], "|", 1))
		inc++;
	input[inc] = NULL;
	*remaining_args = (*remaining_args) + inc + 1;
	return input;
}

int count_procs()
{
	char **input = state->args;
	int ret = 1;
	for(int i = 0; i < state->num_args; i++) {
		if(!strncmp(input[i], "|", 2))
			ret++;
	}
	return ret;	
}

int count_args(char **args)
{
	int ret = 0;
	while(*args != NULL) {
		args = args + 1;
		ret++;
	}
	return ret;
}
/*
int redirect_stdin(char **args)
{
	int size = count_args(args);
	if(size < 3)
		return STDIN_FILENO;
	if(strncmp(args[size-2], "<", 2))
		return STDIN_FILENO;
	args[size-2] = NULL;
	char *file_name = args[size-1];
	return open(file_name, O_RDONLY);
}

int redirect_stdout(char **args)
{
	int size = count_args(args);
	if(size < 3)
		return STDOUT_FILENO;
	if(strncmp(args[size-2], ">", 2))
		return STDOUT_FILENO;
	args[size-2] = NULL;
	const char *file_name = args[size-1];
	int ret;
	if((ret = open(file_name, O_CREAT | O_TRUNC | O_RDWR, 0664)) < 0) {
		debug("Failed to redirect stdout: %i", errno);
	}
	return ret;
}
*/

void execute_program(char *name)
{
	pid_t pid;
	int initial_in_file, final_out_file, process_std_in, i;
	pid_t pgid = 0;
	int run_in_foreground;

	group *new_group = w_calloc(sizeof(group), 1);

	int num_procs = state->num_procs;

	int *pipe_array = w_calloc(2*sizeof(int *), num_procs - 1);
	for(i = 0; i < num_procs - 1; i++) {
		pipe(pipe_array+(2*i));
		debug("Pipe %i: read = %i, write = %i", i, pipe_array[2*i], pipe_array[2*i+1]);
	}
	
	sigset_t maskall, maskchild, maskprev, maskcont;
	sigfillset(&maskall);
	sigemptyset(&maskchild);
	sigemptyset(&maskcont);
	sigaddset(&maskchild, SIGCHLD);
	sigaddset(&maskcont, SIGCONT);

	sigprocmask(SIG_BLOCK, &maskchild, &maskprev);
	sigprocmask(SIG_BLOCK, &maskcont, NULL);
	for(i = 0; i < num_procs; i++) {
		char **proc_args = state->args;
		if(i == 0)
			process_std_in = state->std_in;
		if(i == num_procs - 1) {
			run_in_foreground = strcmp(state->args[state->num_args - 1], "&");
			if(!run_in_foreground) {
				state->args[state->num_args - 1] = NULL;
				state->num_args--;
			}
		}
		if((pid = fork()) == 0) {
			int sig_holder;
			signal(SIGINT, SIG_DFL);
			signal(SIGSTOP, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);
			sigwait(&maskcont, &sig_holder);
			sigprocmask(SIG_SETMASK, &maskprev, NULL);
			

			if(i != 0) {
				initial_in_file = pipe_array[2*i-2];
				dup2(initial_in_file, STDIN_FILENO);
				debug("Process %i reading from fd %i", i, pipe_array[2*i-2]);
			}
			else {
				if(run_in_foreground)
					tcsetpgrp(STDIN_FILENO, getpid());
				dup2(process_std_in, STDIN_FILENO);
			}

			if(i != num_procs - 1){
				final_out_file = pipe_array[2*i+1];
				dup2(final_out_file, STDOUT_FILENO);
				debug("Process %i writing to fd %i", i, pipe_array[2*i+1]);
			}
			else {
				dup2(state->std_out, STDOUT_FILENO);
			}

			for(int j = 0; j < 2*(num_procs - 1); j++) {
					close(pipe_array[j]);
			}


			if(!strncmp(proc_args[0], "help", 5))
				help();
			else if(!strncmp(proc_args[0], "pwd", 4))
				pwd();
			else {
				if(execvp(proc_args[0], proc_args) < 0) {
					fprintf(stdout, EXEC_NOT_FOUND, 
						(proc_args[0]));
					//err = 1;
					cleanup(1);
					raise(SIGKILL);
				}
			}
		}
		else {
			sigprocmask(SIG_BLOCK, &maskall, NULL);
			if(pgid == 0)
				pgid = pid;
			setpgid(pid, pgid);
			if(i != num_procs-1) {
				state->num_args = 0;
				tokenize_input(state->procs[i+1]);
			}
			add_job(new_group, pid);
		}
	}
	for(int i = 0; i < 2*(num_procs - 1); i++) 
		close(pipe_array[i]);
	new_group->pgid = pgid;
	new_group->name = name;
	add_group(&(state->groups), new_group);
	sigprocmask(SIG_SETMASK, &maskprev, NULL);
	if(num_procs > 1)
		free(pipe_array);
	if(run_in_foreground)
		foreground(new_group);
	else
		killpg(new_group->pgid, SIGCONT);
}

void set_color(char *color)
{
	if(color == NULL)
		return;
	if(!strcmp(color, "RED"))
		state->color = KRED;
	else if(!strcmp(color, "GRN"))
		state->color = KGRN;
	else if(!strcmp(color, "YEL"))
		state->color = KYEL;
	else if(!strcmp(color, "BLU"))
		state->color = KBLU;
	else if(!strcmp(color, "MAG"))
		state->color = KMAG;
	else if(!strcmp(color, "CYN"))
		state->color = KCYN;
	else if(!strcmp(color, "WHT"))
		state->color = KWHT;
	else if(!strcmp(color, "BWN"))
		state->color = KBWN;
	else if(!strcmp(color, "DFL"))
		state->color = KNRM;
	else
		printf(BUILTIN_ERROR, "color not found");
	make_prompt();
}


int execute_builtin(char *command)
{
	if(!state->tty)
		putchar('\n');
	if(!strcmp(state->args[0], "exit")) {
		fflush(stdout);
		cleanup(0);
		state->exited = 1;
		return 1;
	}
	if(!strcmp(state->args[0], "cd")) {
		if(state->num_args == 1)
			change_directory(NULL);
		else
			change_directory(state->args[1]);
		return 1;
	}
	if(!strcmp(state->args[0], "jobs")) {
		print_jobs();
		return 1;
	}
	if(!strcmp(state->args[0], "fg")) {
		char *arg = state->args[1];
		if(arg == NULL) {
			printf(BUILTIN_ERROR, "no such job");
			return 1;
		}
		char *end = NULL;
		int job_id = strtol(arg+1, &end, 10);
		group *gp;
		if(arg[0] != '%' || arg+1 == end || *end != 0 || 
			(gp = group_from_jid(&(state->groups), job_id)) == NULL) {
			printf(BUILTIN_ERROR, "no such job");
		}
		else {
			foreground(gp);
		}
		return 1;
	}
	if(!strcmp(state->args[0], "kill")) {
		char *arg = state->args[1];
		group *gp;
		char *end = NULL;
		if(arg == NULL) {
			printf(BUILTIN_ERROR, "no such job");
			return 1;
		}
		if(arg[0] == '%') {
			int job_id = strtol(arg+1, &end, 10);
			if(arg+1 == end || *end != 0 || (gp = group_from_jid(&(state->groups), job_id)) == NULL)
				printf(BUILTIN_ERROR, "no such job");
			else
				killpg(gp->pgid, SIGKILL);
		}
		else {
			pid_t job_pgid = strtol(arg, &end, 10);
			if(arg == end || *end != 0)
				printf(BUILTIN_ERROR, "no such job");
			else
				killpg(job_pgid, SIGKILL);
		}
		return 1;

	}
	if(!strcmp(state->args[0], "color")) {
		set_color(state->args[1]);
		return 1;
	}
	return 0;
}

void help()
{
	w_write(STDOUT_FILENO, HELP_LIST, strlen(HELP_LIST));
	cleanup(1);
	exit(0);
}

void pwd()
{
	char n = '\n';
	w_write(STDOUT_FILENO, state->current_working_directory, state->cwd_size);
	w_write(STDOUT_FILENO, &n, 1);
	cleanup(1);
	exit(0);
}


void change_directory(char *arg)
{
	if(arg == NULL) {
		chdir(getenv("HOME"));
		set_current_working_directory();
	}
	else if(*arg == '-') {
		if(state->previous_working_directory != NULL) {
			chdir(state->previous_working_directory);
			set_current_working_directory();
		}
	}
	else if(!chdir(arg))
		set_current_working_directory();
	else {
		printf(BUILTIN_ERROR, "directory error");
		fflush(stdout);
	}
	make_prompt();
	return;
}


void cleanup_after_command()
{

	if(state->std_in != STDIN_FILENO)
		close(state->std_in);
	if(state->std_out != STDOUT_FILENO)
		close(state->std_out);

	free(state->input);
	if(state->input_buf_size > INITIAL_INPUT_BUFF_SIZE) 
		state->input_buf_size = INITIAL_INPUT_BUFF_SIZE;
	state->input = w_calloc(INITIAL_INPUT_BUFF_SIZE, 1);

	free(state->args);
	if(state->args_size > INITIAL_ARGS_SIZE)
		state->args_size = INITIAL_ARGS_SIZE;
	state->args = w_calloc(INITIAL_ARGS_SIZE, sizeof(char *));

	free(state->procs);
	if(state->procs_size > INITIAL_PROCS_SIZE)
		state->procs_size = INITIAL_PROCS_SIZE;
	state->procs = w_calloc(INITIAL_PROCS_SIZE, sizeof(char *));

	state->input_len = 0;
	state->line_len = 0;
	state->len_prev_lines = 0;
	state->cursor_pos = 0;
	state->in_quotes = 0;
	state->num_args = 0;
	state->num_procs = 0;
	if(!state->tty) {
		
		printf("%s", state->prompt);
		fflush(stdout);
		write_right_prompt();
		fflush(stdout);
	}
}


