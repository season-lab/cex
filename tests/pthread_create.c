#include <stdio.h>
#include <pthread.h>

void* fun(void* a)
{
    (void)a;
    puts("fun()");
    return NULL;
}

int main(int argc, char const *argv[])
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, &fun, NULL))
        return 1;
    if (pthread_join(tid, NULL))
        return 2;
    return 0;
}
