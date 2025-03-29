#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#define MAX_SYSCALLS 500  
#define CSV_FILENAME "syscalls.csv"


char *syscall_names[MAX_SYSCALLS] = {NULL};
char *syscall_descriptions[MAX_SYSCALLS] = {NULL};


void load_syscalls_from_csv(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen syscalls file");
        exit(1);
    }
    char line[1024];
   
    if (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "index", 5) != 0) {
        
            fseek(fp, 0, SEEK_SET);
        }
    }
    while (fgets(line, sizeof(line), fp)) {
       
        line[strcspn(line, "\n")] = 0;
       
        char *token = strtok(line, ",");
        if (token == NULL)
            continue;
        int index = atoi(token);
        if (index < 0 || index >= MAX_SYSCALLS)
            continue;
        
        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        syscall_names[index] = strdup(token);
       
        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        syscall_descriptions[index] = strdup(token);
    }
    fclose(fp);
}

void usage(const char *progname) {
    fprintf(stderr, "Uso: %s [opciones rastreador] Prog [opciones de Prog]\n", progname);
    fprintf(stderr, "Opciones rastreador:\n");
    fprintf(stderr, "   -v  : Muestra detalles de cada system call\n");
    fprintf(stderr, "   -V  : Igual que -v, pero pausa hasta que el usuario presione una tecla\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
    }

  
    load_syscalls_from_csv(CSV_FILENAME);

 
    int verbose = 0;
    int pause_on_verbose = 0;
    int index = 1;
    while (index < argc && argv[index][0] == '-') {
        if (strcmp(argv[index], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[index], "-V") == 0) {
            verbose = 1;
            pause_on_verbose = 1;
        } else {
            break;
        }
        index++;
    }
    if (index >= argc) {
        usage(argv[0]);
    }

   
    char *prog = argv[index];
    char **child_args = &argv[index];

 
    int syscall_counts[MAX_SYSCALLS] = {0};

    pid_t child = fork();
    if (child == 0) {
        
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace TRACEME");
            exit(1);
        }
       
        kill(getpid(), SIGSTOP);
       
        execvp(prog, child_args);
        perror("execvp");
        exit(1);
    } else if (child > 0) {
        int status;
       
        waitpid(child, &status, 0);
       
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
            perror("ptrace SYSCALL");
            exit(1);
        }
        while (1) {
            waitpid(child, &status, 0);
            if (WIFEXITED(status))
                break;  

            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
                perror("ptrace GETREGS");
                exit(1);
            }
           
            long syscall = regs.orig_rax;
            if (syscall < MAX_SYSCALLS) {
                syscall_counts[syscall]++;
                const char *name = (syscall_names[syscall] != NULL) ? syscall_names[syscall] : "desconocido";
                const char *desc = (syscall_descriptions[syscall] != NULL) ? syscall_descriptions[syscall] : "Sin descripción";
                if (verbose) {
                    printf("System call: %ld (%s)\n\tDescripción: %s\n", syscall, name, desc);
                    fflush(stdout);
                    if (pause_on_verbose) {
                        printf("Presione Enter para continuar...");
                        getchar();
                    }
                }
            }
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
                perror("ptrace SYSCALL");
                exit(1);
            }
        }
        
        printf("\nResumen de system calls:\n");
        printf("%-20s %s\n", "System Call", "Cantidad");
        for (int i = 0; i < MAX_SYSCALLS; i++) {
            if (syscall_counts[i] > 0) {
                const char *name = (syscall_names[i] != NULL) ? syscall_names[i] : "desconocido";
                printf("%-20s %d\n", name, syscall_counts[i]);
            }
        }
    } else {
        perror("fork");
        exit(1);
    }
    return 0;
}
