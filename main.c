#include "pe_analyzer.h"
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#define NUM_OF_MIN_FILES 2

int main(int argc, char *args[])
{
    if (argc < NUM_OF_MIN_FILES){
        printf("Usage: %s <PE_FILE>\n", args[0]);
        return -1;
    }

    pe_analyzer pe_a = {0};

    int status = peLoad(&pe_a, args[1]);

    if(status != PE_SUCCESS)
        printf("Error code: %d\n", status);

    freeResources(&pe_a);
    return 0;
}