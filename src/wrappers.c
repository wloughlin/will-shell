#include <stdlib.h>
#include <unistd.h>
#include "debug.h"

void *w_malloc(size_t size)
{
	void *ret;
	if((ret = malloc(size)) == NULL)
	{
		debug("MALLOC FAILURE!\n");
		exit(1);
	}
	return ret;
}

void *w_calloc(size_t nitems, size_t size)
{
	void *ret;
	if((ret = calloc(nitems, size)) == NULL)
	{
		debug("CALLOC FAILURE!\n");
		exit(1);
	}
	return ret;
}


void *w_realloc(void *ptr, size_t size)
{
	void *ret;
	if((ret = realloc(ptr, size)) == NULL)
	{
		debug("CALLOC FAILURE!\n");
		exit(1);
	}
	return ret;
}

ssize_t w_write(int fd, const void* buf, size_t nbytes)
{
	ssize_t ret;
	if((ret = write(fd, buf, nbytes)) < 0) {
		debug("WRITE FAILURE\n");
		exit(1);
	}
	return ret;
}