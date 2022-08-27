#include <stdio.h>

int main(void)
{

    char *r = "%20c";
    char s[100];

    sprintf(s, r);
    printf("%s", s);
    return (0);
}