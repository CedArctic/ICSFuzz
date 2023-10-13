#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "mutator.h"

#define LEN 128
#define MAX_LINE_LENGTH 80

// Function to get Process ID (PID) based on the process name
int get_pid(char *pid_name) {

	char ch;
	char *line = malloc(LEN*sizeof(char));
	int iter = 0;
	
	char *src = malloc(LEN*sizeof(char));
	int retval;
	
	strcpy(src, "pidof ");	
	
	if((strlen(src)+strlen(pid_name))>LEN)
		return(0);
	else
		strcat(src, pid_name);

	FILE *cmd = popen(src, "r");
	
	if(cmd==NULL){
		printf("Unable to open process");
		return(1);
	}

	while(((ch=fgetc(cmd)) != '\n')&&(iter<LEN))
		line[iter++] = ch;
	
	retval = atoi(line);
	
	pclose(cmd);
	free(line);
	free(src);
	return(retval);
}


// Function to get the thread ID of the main Codesys task
// ICSFuzz assumes that the main project task is named "PLC_Task". Otherwise this fails.
int get_tid(int pid) {

	char ch;
	char *line = NULL;
	char *token = NULL;
	char *src = malloc(LEN*sizeof(char));
	char *pid_str = malloc((pid/10+1)*sizeof(char));
	const char delim[2] = " ";
	int iter = 0;
	int retval = 0;
	size_t len =0;
	ssize_t read;
	
	
	// Run "ps -AT | grep codesys_pid" to get the thread IDs of the threads spawned by the codesys runtime
	strcpy(src, "ps -AT | grep ");	
	sprintf(pid_str, "%d", pid);
	strcat(src, pid_str);
	
	FILE *cmd = popen(src, "r");

	
	if(cmd==NULL){
		printf("Unable to open process");
		return(1);
	}
	

	// Parse the output and try to find the "PLC_Task" string for the main project.
	// If the main project is not named PLC_Task, rename it, otherwise this fails.
	while((read = getline(&line, &len, cmd)) != -1){
		iter = 0;
		while((line[iter] != '_')&&(iter<read))
			iter++;
		
		if((line[iter-1]=='C') && (line[iter+1]=='T')){
			token = strtok(line, delim);
			token = strtok(NULL, delim);
			retval = atoi(token);
			break;
		}
		else
			continue;
	}

	// Free used buffers	
	free(pid_str);
	free(src);
	pclose(cmd);
	return(retval);
}


// This function finds the stack memory area of the given thread id by inspecting the proc maps file 
// WARNING: This method requires that that we're using version 3.x of the Linux Kernel. 
// Newer versions of the kernel do not indicate the part of the stack that belongs to each thread
// See: https://stackoverflow.com/questions/45423786/how-to-find-stack-memory-segments-in-newer-linux-kernels
int addr_calc(char *proc_maps, int tid){
	
	// Open the proc maps file
	FILE *fd_proc_maps = fopen(proc_maps, "r");
	if (!fd_proc_maps) {
		printf("Could not open %s\n", proc_maps);
		perror(proc_maps);
 		return EXIT_FAILURE;
	}
	
	// Buffer to store lines from the proc maps file
	char lines[25][MAX_LINE_LENGTH] = {0};
	
	// Counter for keeping track of lines read
	unsigned int line_count = 0;
	
	// Variable to store return value
	int retval;
	
	// Temporary variable to store 
	int tempid;
	
	// Read the first 20 lines in the proc maps file, and store them into the lines[][] buffer
	while((fgets(lines[line_count], MAX_LINE_LENGTH, fd_proc_maps))&&(line_count<20))
		line_count++;		

	// Pointer, delimiters, and iteration counter used for parsing
	char *token = NULL;	
	char delim[4][2] = {"]",
	 		    "[",
			    ":",
			    "-"};
	int i=1;

	// Example lines buffer entry: 7fe84c200000-7fe84ca00000 rw-p 00000000 00:00 0    [stack:25672]
	// 7fe84c200000-7fe84ca00000 indicates the address rangeof the thread stack
	// [stack:25672] indicates the thread ID to which this stack belongs to

	// We focus on the 12th line where we expect the PLC_Task thread id to be found
	// This line strips the ] from the string
	token = strtok(lines[12], delim[0]);
	
	// Repeatedly split the string at the delimiters to locate the thread ID
	while((token != NULL)&&(i<3)){
		token = strtok(token, delim[i]);
		token = strtok(NULL, delim[i]);
		i++;
	}
	
	// Parse the thread ID, otherwise fail
	if(token!=NULL){
		tempid = atoi(token);
		token = NULL;
	}
	else{
		printf("Tokenization process failed\n");
		return 1;
	}

	// If the PLC_Task thread ID is not on the 12th line, the thread stack is considered out of alignment
	if(tempid!=tid){
		printf("Thread stack is out of alignment. Please reboot your PLC\n");
		return 1;
	}
	else{
		// Otherwise look on line 18, and split on the "-" delimiter to find the starting value of 
		// the stack memory range belonging to KBUS presumably
		token = strtok(lines[18], delim[3]);
		retval = atoi(token);	
	}
	
	// Close the proc maps file
	if(fclose(fd_proc_maps)){
		return EXIT_FAILURE;
		perror(proc_maps);
	}

	// Return the start point of the kbus memory
	return retval;
}
		
	
// ICSFuzz entry point
int main(int argc, char* argv[]) {

	// Check if input arguments are valid
 	if (argc != 3) {
		printf("proc-2  pid  addr  length\n");
 		exit(1);
	}

	// Find the process ID of the codesys runtime
	int pid = get_pid("codesys3");
	if(pid==0){
		printf("Could not open process. Please check if the codesys3 runtime is open.\n");
		exit(1);
	}

	// Get the thread ID of the main user code thread. ICSFuzz expects this to be named PLC_Task
	// If not, this will fail. To avoid this, rename the main task to PLC_Task in Codesys IDE
	int taskid = get_tid(pid);   
 	 if(taskid==0){
		printf("PLC Task is not initialized/running. Please restart it through the Codesys or Wago HMI.\n");
		exit(1);
	}
	
	// Parse input arguments: 
	unsigned long addr = strtoul(argv[1], NULL, 16);
	int len  = strtol (argv[2], NULL, 10);

	// Form /proc/pid/mem and /proc/pid/maps strings.
	// /proc/pid/maps shows the memory structure and the areas of the memory area of the process.
	// /proc/pid/mem is the actual virtual memory of the process.
	// Source: https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
	char* proc_mem = malloc(50);
	sprintf(proc_mem, "/proc/%d/mem", pid);
	
	char* proc_maps = malloc(50);
	sprintf(proc_maps, "/proc/%d/maps", pid);

	// Find the memory area associated with KBUS (presumably)
	// Currently this calculated address is not used by the fuzzer for some reason.
	int tempy = addr_calc(proc_maps, taskid);
	int in_addr = 0x0;
	if((tempy==EXIT_FAILURE)||(tempy==1))
		exit(1);
	else
		in_addr = tempy+0x12;

	//printf("PLC input fuzzing address is %d\n", in_addr);
	
	// Open the codesys runtime memory
	printf("opening %s, address is 0x%lx\n", proc_mem, addr);
	int fd_proc_mem = open(proc_mem, O_RDWR);
	if (fd_proc_mem == -1) {
		printf("Could not open %s\n", proc_mem);
		exit(1);
	}

	// Create a buffer for the input to the fuzzer
	char *buf = malloc(len);
	int seed_input = 0xdeadbeef;
	sprintf(buf, "%d", seed_input);
                    
	// Move the fd_proc_mem memory pointer to the address used for fuzzing
	lseek(fd_proc_mem, addr, SEEK_SET);
	
	// Main fuzzing loop
	while(1){
		// The fuzzing engine mutates the input in the buffer, uses it for fuzzing, and then returns it as retval
		uint32_t retval = fuzzing_engine(fd_proc_mem, addr, buf, len);
		// Place the mutated fuzzer output back into the input buffer, for use in the next loop
		// If we want to keep track of inputs that crash the application, we need to output this to a log file
		sprintf(buf, "%d", retval);
	}
	
	// Free memory before exiting
	free(buf);
	free(proc_mem);
	free(proc_maps);

	return 0;

}
