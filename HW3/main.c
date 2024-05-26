#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <elf.h>
#include <fcntl.h>
#include <capstone/capstone.h>
#include <sys/user.h>

#define MB 10 //max breakpoints
bool loaded = false;
pid_t child_pid = 0;

struct breakpoint {
    uint64_t addr;
    long original_data;  // 存储原始指令数据
    bool enabled;
};

struct breakpoint breakpoints[MB];
int nbp = 0;

bool check_bp() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    uint64_t pc = regs.rip; //next instruction

    for (int i = 0; i < nbp; i++) {
        if (breakpoints[i].enabled && pc == breakpoints[i].addr) {
            printf("** Hit breakpoint at 0x%lx\n", pc);
            // 处理断点逻辑，如恢复原始指令等
            return true;
        }
    }
    return false;
}

void set_breakpoint(uint64_t addr) {
    if (nbp >= MB) {
        printf("** Maximum number of breakpoints reached.\n");
        return;
    }

    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    breakpoints[nbp].addr = addr;
    breakpoints[nbp].original_data = data;
    breakpoints[nbp].enabled = true;
    printf("** set a breakpoint at 0x%lx.\n", addr);
    nbp++;
}

void disassemble_instruction(uint64_t address) {
    csh handle;
    cs_insn *insn;
    size_t count;
    const int code_size = 64;  // 增加读取的字节数，以确保能涵盖多个指令
    unsigned char code[code_size];

    // 初始化 Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }

    // 从内存地址读取机器码
    for (int i = 0; i < code_size; i += sizeof(long)) {
        *(long *)(code + i) = ptrace(PTRACE_PEEKTEXT, child_pid, address + i, NULL);
    }

    // 反汇编读取到的机器码
    count = cs_disasm(handle, code, sizeof(code), address, 0, &insn);
    if (count > 0) {
        if (count > 5)  // 限制最多显示5条指令
            count = 5;
        for (size_t j = 0; j < count; j++) {
            printf("      %lx: ", insn[j].address);

            char byte_string[32];  // 大于最长可能的字节序列的字符串
            int pos = 0;
            // 将每个字节格式化成字符串，并存入 byte_string
            for (int k = 0; k < insn[j].size; k++) {
                pos += snprintf(byte_string + pos, sizeof(byte_string) - pos, "%02x ", insn[j].bytes[k]);
            }

            printf("%-20s", byte_string); // 使用固定宽度输出字节字符串
            printf("\t%s\t\t%s\n", insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("ERROR: Failed to disassemble instructions\n");
    }
    cs_close(&handle);
}

void load_program(const char* program) {
    if (loaded) {
        printf("** Program is already loaded.\n");
        return;
    }

    child_pid = fork();
    if (child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(program, program, NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {  // 父进程
        int status;
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("** Failed to start the program.\n");
        } else {
            int fd = open(program, O_RDONLY);
            Elf64_Ehdr ehdr;
            read(fd, &ehdr, sizeof(Elf64_Ehdr));
            printf("** program '%s' loaded. entry point 0x%lx.\n", program, ehdr.e_entry);
            close(fd);
            loaded = true;
            disassemble_instruction(ehdr.e_entry);
        }
    } else {
        perror("fork");
        exit(1);
    }
}

void si() {
    int status;
    struct user_regs_struct regs;

    // 执行单步指令
    ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
    waitpid(child_pid, &status, 0);

    if (WIFEXITED(status)) {
        printf("** The target program terminated.\n");
        loaded = false;  // 程序已终止，更新加载状态
        return;
    } else if (WIFSTOPPED(status)) {
        // 获取当前寄存器状态，特别是指令指针寄存器
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        check_bp();
        uint64_t pc = regs.rip;  // Program Counter (RIP 寄存器的值)
        disassemble_instruction(pc);
    }
}


void handle_command(char* command) {
    if (!loaded && strncmp(command, "load ", 5) != 0) {
        printf("** Please load a program first.\n");
        return;
    }

    if (strncmp(command, "load ", 5) == 0) {
        char* program = command + 5;
        int newline=0;
        while(program[newline] != '\n')
            newline++;
        program[newline] = '\0';
        load_program(program);
    } else if (strncmp(command, "break", 5) == 0) {
        char* addr_str = command + 6;
        int newline=0;
        while(addr_str[newline] != '\n')
            newline++;
        addr_str[newline] = '\0';
        uint64_t addr = strtoul(addr_str, NULL, 16);
        set_breakpoint(addr);
    } else if (strncmp(command, "cont", 4) == 0 && loaded) {
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    } else if (strncmp(command, "quit", 4) == 0) {
        printf("Exiting debugger.\n");
        exit(0);
    }
    else if (strncmp(command, "si", 2) == 0){
        si();
    }
    else if (strncmp(command, "info break", 10) == 0){
        if(nbp == 0)
            printf("** no breakpoints.\n");
        else{
            printf("Num\tAddress\n");
            for(int i=0; i<MB; i++){
                if(breakpoints[i].enabled){
                    printf("%d\t0x%lx\n", i, breakpoints[i].addr);
                }
            }
        }

    }
    else {
        printf("Unknown command.\n");
    }
}

int main(int argc, char *argv[]) {
    char command[128];

    if (argc == 2) {
        load_program(argv[1]);  // Load program immediately if provided
    }

    // Main command loop
    while (1) {
        printf("(sdb) ");
        if (fgets(command, sizeof(command), stdin) == NULL) {
            printf("\n");
            break;  // If input ends, exit loop
        }
        // Handle user input command
        handle_command(command);
    }

    return 0;
}
