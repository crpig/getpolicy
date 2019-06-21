#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "myext4_crypt.h"

int main(int argc, char *argv[])
{
    int index = 1;
	if (argc < 2)
    {
        printf("wrong arg\n");
    }

    for(index=1; index<argc; index++)
        e4crypt_policy_print(argv[index]);
}