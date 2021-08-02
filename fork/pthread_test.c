#include "apue.h"
#include <pthread.h>

pthread_t ntid;

void printids(const char *s)
{
	pid_t pid;
	pthread_t tid;

	pid=getpid();
	tid=pthread_self();
	printf("%s pid %lu tid %lu (0x%lx)\n",s,(unsigned long)pid,(unsigned long)tid,(unsigned long)tid);
}

void *thr_fn(void *arg)
{
	printids("new thread:");
	sleep(30);
	return((void *)0);
}

int main(void){
	int i;
	long err;
	for(i=1;i<30;i++)
	{
		if((err=pthread_create(&ntid,NULL,thr_fn,NULL))!=0)
			err_exit(err,"can't create thread");
		printids("main thread:");
		sleep(1);
	}
	exit(0);
}
