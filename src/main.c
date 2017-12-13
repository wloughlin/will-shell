#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "will_shell.h"
#include "will_shell_helper.h"
#include "wrappers.h"
#include "debug.h"

int main(int argc, char *argv[], char* envp[]) {
    //char *last_input;

    int is_tty = 0;

    if(!isatty(STDIN_FILENO)) {
        is_tty = 1;
    }
    setup(is_tty);
    if(!is_tty) {
        w_write(STDOUT_FILENO, state->prompt, state->prompt_size);
        write_right_prompt();
        fflush(stdout);
    }

    do {
        read_bytes_to_input(STDIN_FILENO);
    } while(!state->exited);

    debug("%s", "user entered 'exit'");
    return EXIT_SUCCESS;
}
