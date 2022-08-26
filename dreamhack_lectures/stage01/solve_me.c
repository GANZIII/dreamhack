#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
  int sz = 0x30;
  char *buf = (char *)malloc(sizeof(char) * sz);
  puts("Hello World!");
  printf("Education + Hack = ?\\n");
  fgets(buf, sz, stdin);
  if (!strncmp(buf, "DreamHack", 9))
    printf("Welcome Hackers :)\\n");
  else
    printf("No No :/n");
  return 0;
}