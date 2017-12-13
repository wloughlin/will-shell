#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"
#include "wrappers.h"


#include "jobs.h"



void add_job(group *list, pid_t pid)
{
	job *new_job = w_calloc(sizeof(job), 1);
	job *current = list->head;
	if(current != NULL) {
		while(current->next != NULL) 
			current = current->next;
		current->next = new_job;
    }
    else {
    	list->head = new_job;
    }
	new_job->pid = pid;
	new_job->next = NULL;
	
	list->size++;
}

void add_group(group_list *list, group *new_group) 
{
	group *current = list->head;
	if(current != NULL) {
		while(current->next != NULL) 
			current = current->next;
		current->next = new_group;
    }
    else {
    	list->head = new_group;
    }
	list->size = list->size + new_group->size;
	new_group->jid = list->next_jid;
	list->next_jid++;
}

void decrement_jid(group *start)
{
	while(start != NULL) {
		start->jid--;
		start = start->next;
	}
}

pid_t delete_job_by_pid(group_list *list, pid_t pid)
{
	group *current = list->head;
	group *last = NULL;
	while(current != NULL) {
		list->size = list->size - delete_pid_from_group(current, pid);
		if(current->size == 0) {
			if(last == NULL)
				list->head = current->next;
			else
				last->next = current->next;
			pid_t ret = current->pgid;
			decrement_jid(current->next);
			list->next_jid--;
			free(current->name);
			free(current);
			return ret;
		}
		last = current;
		current = current->next;
	}
	return 0;
}


int delete_pid_from_group(group *list, pid_t pid)
{
	job *current = list->head;
	job *last = NULL;
	while(current != NULL && current->pid != pid) {
		last = current;
		current = current->next;
	}
	if(current == NULL) {
		return 0;
	}
	if(last == NULL)
		list->head = current->next;
	else
		last->next = current->next;
	free(current);
	list->size--;
	return 1;
}

void delete_group_list(group_list *list)
{
	group *g_to_del = list->head;
	while(g_to_del != NULL) {
		job *to_delete = g_to_del->head;
		while(to_delete != NULL) {
			kill(to_delete->pid, SIGKILL);
			job *temp = to_delete->next;
			free(to_delete);
			to_delete = temp;
		}
		group *g_temp = g_to_del->next;
		free(g_to_del->name);
		free(g_to_del);
		g_to_del = g_temp;
	}
}


int list_has_pgid(group_list *list, pid_t pgid) 
{
	group *current = list->head;
	while(current != NULL) {
		if(current->pgid == pgid)
			return 1;
		current = current->next;
	}
	return 0;
}

group *group_from_jid(group_list *list, int jid)
{
	group *current = list->head;
	while(current != NULL) {
		if(current->jid == jid)
			return current;
		current = current->next;
	}
	return NULL;
}





















