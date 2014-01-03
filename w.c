#include <stdlib.h>

int
one (int argc, char *argv[])
{
  int sum = 0;
  while (argc > 1)
    sum += argv[--argc][0] - '0';
  return sum;
}

int
two (int argc, char *argv[])
{
  int sum = 0;
  while (argc > 1)
    sum += atoi (argv[--argc]);
  return sum;
}
