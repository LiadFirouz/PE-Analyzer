#include "pe_analyzer.h"
#include <unistd.h>
#include <errno.h>

void pe_analyzer(){

}

pe_status_t peLoad (pe_analyzer *ctx, const char *filepath){
    // Basic pointer safety checks
    if (ctx == NULL || filepath == NULL) {
        return PE_ERROR_FILE_OPEN;
    }

    // Open the file
    in fd = open(filepath, O_RDONLY);
    printf("fd = %d\n", fd);

    if (fd == -1) {

        // Print which type of error the code have
        perror("Failed to open file");        
        return PE_ERROR_FILE_OPEN;
    }

    // Get the file size using fstat
    struct stat file_info;

    // Call fstat passing the file descriptor and structure address
    if (fstat(fd, &file_info) == -1) {
        perror("Error retrieving file status");
        close(fd);
        return PE_ERROR_STAT;
    }
    
    if (file_info.st_size < 64) {
        perror("Error retrieving file size smaller than 64 bits");
        close(fd);
        return PE_ERROR_FILE_TOO_SMALL;
    }

    if(mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)){
        
    }

    // Extract and print information
    printf("File Size: %ld bytes\n", (long)file_info.st_size);
    printf("Inode Number: %ld\n", (long)file_info.st_ino);

    // Clean up by closing the descriptor
    close(fd);
    return 0;
}
