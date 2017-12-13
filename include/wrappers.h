#ifndef WRAPPERS
#define WRAPPERS

void *w_malloc(size_t size);
void *w_calloc(size_t nitems, size_t size);
void *w_realloc(void *ptr, size_t size);
ssize_t w_write(int fd, const void* buf, size_t nbytes);

#endif