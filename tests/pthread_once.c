#include <stdio.h>
#include <pthread.h>

pthread_once_t once_control = PTHREAD_ONCE_INIT;

void init_routine()
{
    puts("init_routine()");
}

int main(int argc, char const *argv[])
{
    pthread_once(&once_control, init_routine);
    return 0;
}
