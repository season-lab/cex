#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
    char* buf = (char*)malloc(sizeof(char) * 100);

    int i;
    for (i = 0; i < 100; ++i)
        buf[i] = 'a';

    free(buf);
    return 0;
}
