# opwrt

##popen()函数的使用
    
    int execute_command(const char *cmd, char *output, size_t size) {
	
        char buf[MAX_SIZE] = {0};
        size_t current_size = 0;
        FILE *fp = popen(cmd, "r");
        if(fp == NULL) {
            perror("popen failed\n");
            output[0] = '\0';
            return -1;
        }
        
        while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
            size_t len = strlen(buf);
            if(len + current_size < size -1) {
                strcpy(output + current_size, buf);
                current_size += len;
            }
        }
        
        if(pclose(fp) == -1) {
            perror("pclose failed\n");
            return -1;
        }
        return 0;
    }