#ifndef JOBS
#define JOBS

typedef struct job job;
typedef struct group group;


struct job {
	pid_t pid;
	job *next;
};

struct group {
	pid_t pgid;
	int size;
	int jid;
	job *head;
	group *next;
	char *name;
};

typedef struct {
	int size;
	int next_jid;
	group *head;
} group_list;

void add_job(group *list, pid_t pid);
void add_group(group_list *list, group *new_group);
pid_t delete_job_by_pid(group_list *list, pid_t pid);
int delete_pid_from_group(group *list, pid_t pid);
void delete_group_list(group_list *list);
int list_has_pgid(group_list *list, pid_t pgid);
group *group_from_jid(group_list *list, int jid);







#endif