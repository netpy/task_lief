#include <stdio.h>
#include <unistd.h>
int main()
{
    int pid;
    pid = fork();
    int i = 0;
    for (i = 0; i < 2; i++)
    {
        if (pid == 0)
        {
            printf("我是大儿子,我的pid是 %d.\n", getpid());
           // sleep(30);
        }
        else if (pid > 0)
        {
            printf("我是父亲 ，我的pid是 %d.\n", getpid());
            pid = fork();
            if (pid == 0)
            {
                printf("我是小女儿,我的pid是 %d.\n", getpid());
            }
            else if (pid > 0)
            {
                printf("我是父亲 ，我的pid是 %d.\n", getpid());
            }
            else
            {
                printf("fork() error.\n");
            }
        }
        else
        {
            printf("fork() error.\n");
        }
    }
    return 0;
}