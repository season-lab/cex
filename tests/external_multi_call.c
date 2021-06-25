#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
    char* buf1 = (char*)malloc(sizeof(char) * 100);
    char* buf2 = (char*)malloc(sizeof(char) * 100);
    char* buf3 = (char*)malloc(sizeof(char) * 100);

    int i;
    for (i = 0; i < 100; ++i)
        buf1[i] = 'a';
    for (i = 0; i < 100; ++i)
        buf2[i] = 'b';
    for (i = 0; i < 100; ++i)
        buf3[i] = 'c';

    free(buf1);
    free(buf2);
    free(buf3);
    return 0;
}
