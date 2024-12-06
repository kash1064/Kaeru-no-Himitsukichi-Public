#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iomanip>  

#include <cstring>
#include <iostream>
#include <string>

void attach_process(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1)
    {
        std::cerr << "Failed to attach process: " << strerror(errno) << std::endl;
        exit(1);
    }
    waitpid(pid, nullptr, 0);
}

unsigned char save_original_byte(pid_t pid, void* addr)
{
    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
    if (errno != 0)
    {
        std::cerr << "PTRACE_PEEKTEXT failed: " << strerror(errno) << std::endl;
        exit(1);
    }
    return static_cast<unsigned char>(data & 0xFF);
}

void set_breakpoint(pid_t pid, void* addr, unsigned char original_byte)
{
    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
    if (errno != 0)
    {
        std::cerr << "PTRACE_PEEKTEXT failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    long modified = (data & ~0xFF) | 0xCC;

    if (ptrace(PTRACE_POKETEXT, pid, addr, modified) == -1)
    {
        std::cerr << "PTRACE_POKETEXT failed: " << strerror(errno) << std::endl;
        exit(1);
    }
}

void print_registers(pid_t pid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        std::cerr << "PTRACE_GETREGS failed: " << strerror(errno) << std::endl;
        exit(1);
    }
    
    std::cout << "Register state:\n";
    std::cout << "RIP: 0x" << std::hex << regs.rip << "\n";
    
    void* addresses[] = {
        (void*)regs.rax, (void*)regs.rbx, (void*)regs.rcx, 
        (void*)regs.rdx, (void*)regs.rsi, (void*)regs.rdi,
        (void*)regs.rbp, (void*)regs.rsp
    };
    const char* reg_names[] = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP"};

    for (int i = 0; i < 8; i++) {
        std::cout << reg_names[i] << ": 0x" << std::hex 
                  << reinterpret_cast<unsigned long>(addresses[i]) << " -> ";
                  
        unsigned char bytes[16];
        
        // 最初の8バイトを読む
        long data1 = ptrace(PTRACE_PEEKTEXT, pid, addresses[i], nullptr);
        if (errno != 0) {
            std::cout << "Memory read failed\n";
            continue;
        }
        memcpy(bytes, &data1, 8);
        
        // 次の8バイトを読む
        long data2 = ptrace(PTRACE_PEEKTEXT, pid, (void*)((char*)addresses[i] + 8), nullptr);
        if (errno != 0) {
            std::cout << "Memory read failed\n";
            continue;
        }
        memcpy(bytes + 8, &data2, 8);
        
        // hexダンプを表示
        for (int j = 0; j < 16; j++) {
            std::cout << std::setfill('0') << std::setw(2) 
                      << (int)bytes[j] << " ";
        }
        
        // ASCIIを表示
        std::cout << "  |";
        for (int j = 0; j < 16; j++) {
            char c = bytes[j];
            std::cout << (isprint(c) ? c : '.');
        }
        std::cout << "|\n";
    }
}
void handle_breakpoint(pid_t pid, void* addr, unsigned char original_byte)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1)
    {
        std::cerr << "PTRACE_GETREGS failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    regs.rip--;

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1)
    {
        std::cerr << "PTRACE_SETREGS failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
    if (errno != 0)
    {
        std::cerr << "PTRACE_PEEKTEXT failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    long restored = (data & ~0xFF) | original_byte;

    if (ptrace(PTRACE_POKETEXT, pid, addr, restored) == -1)
    {
        std::cerr << "PTRACE_POKETEXT failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1)
    {
        std::cerr << "PTRACE_SINGLESTEP failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    waitpid(pid, nullptr, 0);
    set_breakpoint(pid, addr, original_byte);
}

void debug_loop(pid_t pid, void* addr, unsigned char original_byte)
{
    while (true)
    {
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1)
        {
            std::cerr << "PTRACE_CONT failed: " << strerror(errno) << std::endl;
            exit(1);
        }
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
        {
            std::cout << "Process " << pid << " exited\n";
            break;
        }

        if (WIFSTOPPED(status))
        {
            if (WSTOPSIG(status) == SIGTRAP)
            {
                std::cout << "Breakpoint hit!\n";
                print_registers(pid);
                handle_breakpoint(pid, addr, original_byte);
            }
        }
    }
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <pid> <breakpoint_address_hex>\n";
        return 1;
    }

    pid_t pid = std::stoi(argv[1]);
    void* addr = reinterpret_cast<void*>(std::stoull(argv[2], nullptr, 16));

    attach_process(pid);
    unsigned char original_byte = save_original_byte(pid, addr);
    set_breakpoint(pid, addr, original_byte);
    debug_loop(pid, addr, original_byte);

    long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
    long restored = (data & ~0xFF) | original_byte;
    ptrace(PTRACE_POKETEXT, pid, addr, restored);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    return 0;
}