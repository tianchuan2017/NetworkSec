// ErrorOut
// Group 1

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

void ErrorOut(char *msg)
{
	printf("%s\n",msg);
	exit(1);
}
