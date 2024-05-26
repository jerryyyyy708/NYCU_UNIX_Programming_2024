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

#define MB 64 //max breakpoints
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
    long int3 = (data & ~0xFF) | 0xCC;

    if (ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)int3) != 0) {
        perror("** Failed to write memory");
        return;
    }

    printf("** set a breakpoint at 0x%lx.\n", addr);
    nbp++;
}

bool should_display(const cs_insn *insn) {
    // 检查指令的机器码和反汇编文本
    if (insn->size == 2 && insn->bytes[0] == 0x00 && insn->bytes[1] == 0x00) {
        // 可能是 "00 00 add byte ptr [rax], al"
        if (strcmp(insn->mnemonic, "add") == 0 && strcmp(insn->op_str, "byte ptr [rax], al") == 0) {
            // 这是我们想要过滤掉的无意义指令
            return false;
        }
    }
    return true;  // 其他情况都显示
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
            if(!should_display(&insn[j])){
                printf("** the address is out of the range of the text section.\n");
                break;
            }
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

void cont() {
    //check if next is breakpoint
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    int temp = -1;

    uint64_t pc = regs.rip;  // Program Counter (RIP 寄存器的值)
    for (int i = 0; i < nbp; i++) {
        if (breakpoints[i].enabled && pc == breakpoints[i].addr) {
            temp = i;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].original_data);
            break;
        }
    }

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    int status;
    waitpid(child_pid, &status, 0);

    // 处理可能的停止原因
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        uint64_t pc = regs.rip - 1;  // Adjust PC because it stops after the INT 3 instruction

        for (int i = 0; i < nbp; i++) {
            if (breakpoints[i].enabled && pc == breakpoints[i].addr) {
                printf("** Hit breakpoint at 0x%lx\n", pc);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].original_data);
                regs.rip = pc;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                disassemble_instruction(pc);
                long int3_instruction = (breakpoints[i].original_data & ~0xFF) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, int3_instruction);
                break;
            }
        }
    } else if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        exit(0);
        loaded = false;
    }

    if(temp != -1 && loaded){
        long int3_instruction = (breakpoints[temp].original_data & ~0xFF) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[temp].addr, int3_instruction);
    }
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

void reset_bp() {
    for (int i = 0; i < MB; i++) {
        if (breakpoints[i].enabled) {
            // 恢复原始数据到内存位置
            if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr,
                       (void*)breakpoints[i].original_data) != 0) {
                perror("Failed to reset breakpoint");
            }
        }
    }
}


void set_bp() {
    for (int i = 0; i < MB; i++) {
        if (breakpoints[i].enabled) {
            long int3_instruction = (breakpoints[i].original_data & ~0xFF) | 0xCC;
            // 设置 INT 3 断点指令
            if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr,
                       (void*)int3_instruction) != 0) {
                perror("Failed to set breakpoint");
            }
        }
    }
}

void si() {
    int status;
    struct user_regs_struct regs;
    
    reset_bp();
    // 执行单步指令
    ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
    waitpid(child_pid, &status, 0);

    if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        exit(0);
        loaded = false;  // 程序已终止，更新加载状态
        return;
    } else if (WIFSTOPPED(status)) {
        // 获取当前寄存器状态，特别是指令指针寄存器
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        check_bp();
        uint64_t pc = regs.rip;  // Program Counter (RIP 寄存器的值)
        disassemble_instruction(pc);
    }
    set_bp();
}

void patch_memory(uint64_t addr, uint64_t value, int len) {
    // 读取现有的内存内容
    errno = 0;
    long existing = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    if (errno) {
        perror("Failed to read memory");
        return;
    }

    // 创建掩码，用于修改指定长度的字节
    uint64_t mask = (1ULL << (len * 8)) - 1;
    // 清除相关字节并应用新值
    long new_value = (existing & ~mask) | (value & mask);

    // 写入新值到内存
    if (ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)new_value) != 0) {
        perror("Failed to patch memory");
        return;
    }

    // 检查并更新断点的 original_data
    for (int i = 0; i < nbp; i++) {
        if (breakpoints[i].enabled && breakpoints[i].addr == addr) {
            printf("** Warning: Patching at breakpoint address. Updating original data.\n");
            breakpoints[i].original_data = new_value;  // 更新为新的值
        }
    }

    printf("** patch memory at address 0x%lx.\n", addr);
}

void info_registers() {
    if (!loaded) {
        printf("** Please load a program first.\n");
        return;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) != 0) {
        perror("Failed to get registers");
        return;
    }

    // 打印所有寄存器，三个一行
    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
}

static int entering = 1;

void trace_syscall() {

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    int temp = -1;

    uint64_t pc = regs.rip;  // Program Counter (RIP 寄存器的值)
    for (int i = 0; i < nbp; i++) {
        if (breakpoints[i].enabled && pc == breakpoints[i].addr) {
            temp = i;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].original_data);
            break;
        }
    }
    
    int status;
    bool notin = true;

    // 让子进程运行到下一个系统调用
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    waitpid(child_pid, &status, 0);
    
    if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        exit(0);
        return;
    }
    else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        uint64_t pc = regs.rip - 1;  // Adjust PC because it stops after the INT 3 instruction

        for (int i = 0; i < nbp; i++) {
            if (breakpoints[i].enabled && pc == breakpoints[i].addr) {
                notin = false;
                printf("** Hit breakpoint at 0x%lx\n", pc);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].original_data);
                regs.rip = pc;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                disassemble_instruction(pc);
                long int3_instruction = (breakpoints[i].original_data & ~0xFF) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, int3_instruction);
                break;
            }
        }
    }


    if(notin){
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        if (entering) {
            // 处理系统调用的进入
            printf("** enter a syscall(%lld) at 0x%llx\n", regs.orig_rax, regs.rip - 2);
            uint64_t pc = regs.rip - 2;
            disassemble_instruction(pc);
        } else {
            // 处理系统调用的离开
            printf("** leave a syscall(%lld) = %lld at 0x%llx\n", regs.orig_rax, regs.rax, regs.rip - 2);
            uint64_t pc = regs.rip - 2;
            disassemble_instruction(pc);
        }

        entering = 1 - entering;  // 切换状态
    }


    if(temp != -1 && loaded){
        long int3_instruction = (breakpoints[temp].original_data & ~0xFF) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[temp].addr, int3_instruction);
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
        cont();
    } else if (strncmp(command, "quit", 4) == 0) {
        printf("Exiting debugger.\n");
        exit(0);
    }
    else if (strncmp(command, "si", 2) == 0){
        si();
    }
    else if (strncmp(command, "info break", 10) == 0){
        bool no_bp = false;
        for(int i=0;i<MB;i++){
            if(breakpoints[i].enabled){
                break;
            }
            if(i == MB-1){
                printf("** no breakpoints.\n");
                no_bp = true;
            }
        }
        if(!no_bp){
            printf("Num\tAddress\n");
            for(int i=0; i<MB; i++){
                if(breakpoints[i].enabled){
                    printf("%d\t0x%lx\n", i, breakpoints[i].addr);
                }
            }
        }
    }
    else if (strncmp(command, "delete", 6) == 0){
        char* bid = command + 6; // the breakpoint id
        int newline=0;
        while(bid[newline] != '\n')
            newline++;
        bid[newline] = '\0';
        int d_bp = atoi(bid); // turn to int
        if(breakpoints[d_bp].enabled){
            breakpoints[d_bp].enabled = false;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[d_bp].addr, (void*)breakpoints[d_bp].original_data);
            printf("** delete breakpoint %d\n", d_bp);
        }
        else
            printf("** breakpoint %d does not exist.\n", d_bp);
    }
    else if (strncmp(command, "patch", 5) == 0) {
        uint64_t addr, value;
        int len;
        if (sscanf(command + 6, "%lx %lx %d", &addr, &value, &len) == 3) {
            // 检查长度是否合法
            if (len == 1 || len == 2 || len == 4 || len == 8) {
                // 调整 value 根据 len
                uint64_t mask = (1ULL << (len * 8)) - 1;
                value &= mask;
                patch_memory(addr, value, len);
            } else {
                printf("** Invalid length for patch. Use 1, 2, 4, or 8.\n");
            }
        } else {
            printf("** Invalid patch command format. Use: patch <address> <value> <len>\n");
        }
    }
    else if (strncmp(command, "info reg", 8) == 0){
        info_registers();
    }
    else if (strncmp(command, "syscall", 7) == 0) {
        trace_syscall();  // 调用跟踪系统调用函数
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
