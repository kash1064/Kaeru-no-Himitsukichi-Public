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

// ハードウェアブレークポイントの状態管理
char hardware_breakpoints[4] = {0,0,0,0};

// 監視条件の定義
#define CONDITION_EXECUTE        0x0
#define CONDITION_WRITE_ONLY    0x1
#define CONDITION_IO_READ_WRITE 0x2
#define CONDITION_READ_WRITE    0x3

// 長さの定義
#define LENGTH_BYTE  0x0
#define LENGTH_WORD  0x1
#define LENGTH_QWORD 0x2
#define LENGTH_DWORD 0x3

void attach_process(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        std::cerr << "Failed to attach process: " << strerror(errno) << std::endl;
        exit(1);
    }
    waitpid(pid, nullptr, 0);
}

// スロット取得
int get_slot(pid_t pid) {
    int Dr6 = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, u_debugreg[6]), 0);
    
    int slot = -1;
    if (Dr6 & 0x1 && hardware_breakpoints[0] == 1) slot = 0;
    else if (Dr6 & 0x2 && hardware_breakpoints[1] == 1) slot = 1;
    else if (Dr6 & 0x4 && hardware_breakpoints[2] == 1) slot = 2;
    else if (Dr6 & 0x8 && hardware_breakpoints[3] == 1) slot = 3;
    
    return slot;
}

// ウォッチポイントの設定
int set_watchpoint(pid_t pid, void* addr, int length, int condition) {
    if (!(0 <= length && 3 >= length)) return -1;
    if (!(0 <= condition && 3 >= condition)) return -1;
    
    // 利用可能なスロットを探す
    int available = -1;
    for (int i = 0; i < 4; i++) {
        if (hardware_breakpoints[i] == 0) {
            available = i;
            break;
        }
    }
    if (available == -1) {
        std::cerr << "No available debug registers\n";
        return -1;
    }

    hardware_breakpoints[available] = 1;

    // DR7の設定
    int Dr7 = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, u_debugreg[7]), 0);
    Dr7 |= 1 << (available * 2);             // Local breakpoint enable
    Dr7 |= condition << (available * 4 + 16); // Condition
    Dr7 |= length << (available * 4 + 18);    // Length

    // デバッグレジスタの設定
    if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[available]), addr) == -1) {
        std::cerr << "Failed to set debug register " << available << std::endl;
        return -1;
    }
    if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[7]), Dr7) == -1) {
        std::cerr << "Failed to set DR7\n";
        return -1;
    }

    return available;
}

void print_registers(pid_t pid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        std::cerr << "PTRACE_GETREGS failed: " << strerror(errno) << std::endl;
        exit(1);
    }
    
    std::cout << "Register state:\n";
    
    void* addresses[] = {
        (void*)regs.rip,
        (void*)regs.rax, (void*)regs.rbx, (void*)regs.rcx, 
        (void*)regs.rdx, (void*)regs.rsi, (void*)regs.rdi,
        (void*)regs.rbp, (void*)regs.rsp
    };
    const char* reg_names[] = {"RIP","RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP"};

    for (int i = 0; i < 8; i++) {
        std::cout << reg_names[i] << ": 0x" << std::hex 
                  << reinterpret_cast<unsigned long>(addresses[i]) << " -> ";
                  
        unsigned char bytes[16];
        
        long data1 = ptrace(PTRACE_PEEKTEXT, pid, addresses[i], nullptr);
        if (errno != 0) {
            std::cout << "Memory read failed\n";
            continue;
        }
        memcpy(bytes, &data1, 8);
        
        long data2 = ptrace(PTRACE_PEEKTEXT, pid, (void*)((char*)addresses[i] + 8), nullptr);
        if (errno != 0) {
            std::cout << "Memory read failed\n";
            continue;
        }
        memcpy(bytes + 8, &data2, 8);
        
        for (int j = 0; j < 16; j++) {
            std::cout << std::setfill('0') << std::setw(2) 
                      << (int)bytes[j] << " ";
        }
        
        std::cout << "  |";
        for (int j = 0; j < 16; j++) {
            char c = bytes[j];
            std::cout << (isprint(c) ? c : '.');
        }
        std::cout << "|\n";
    }
}

void remove_watchpoint(pid_t pid, int slot) {
    if (slot < 0 || slot > 3) return;
    
    // DR7のフラグをクリア
    int Dr7 = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, u_debugreg[7]), 0);
    Dr7 &= ~(1 << (slot * 2));             // Local breakpoint disable
    Dr7 &= ~(3 << (slot * 4 + 16));        // Clear condition
    Dr7 &= ~(3 << (slot * 4 + 18));        // Clear length
    
    // デバッグレジスタをクリア
    ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[slot]), 0);
    ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[7]), Dr7);
    
    hardware_breakpoints[slot] = 0;
}

void inject_infinite_loop(pid_t pid, void* addr) {
    // 現在の命令を保存
    long original_data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
    
    // 下位2バイトを eb fe (JMP $-2 = infinite loop) に書き換え
    long new_data = (original_data & ~0xFFFF) | 0xfeeb;
    
    // 書き換えた命令を書き込み
    if (ptrace(PTRACE_POKETEXT, pid, addr, new_data) == -1) {
        std::cerr << "Failed to write infinite loop: " << strerror(errno) << std::endl;
        exit(1);
    }
}

void debug_loop(pid_t pid, void* addr) {
    while (true) {
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
            std::cerr << "PTRACE_CONT failed: " << strerror(errno) << std::endl;
            exit(1);
        }
        
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            std::cout << "Process " << pid << " exited\n";
            break;
        }

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            std::cout << "Watchpoint hit!\n";
            print_registers(pid);
            
            // スロット情報の取得
            int slot = get_slot(pid);
            if (slot != -1) {
                std::cout << "Triggered by debug register " << slot << std::endl;
                
                // レジスタ情報を取得してRIPのアドレスを特定
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
                    std::cerr << "Failed to get registers: " << strerror(errno) << std::endl;
                    exit(1);
                }
                
                // 無限ループを注入
                inject_infinite_loop(pid, (void*)regs.rip);
                
                // watchpointを削除
                remove_watchpoint(pid, slot);
                
                // プロセスをデタッチ
                if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == -1) {
                    std::cerr << "Failed to detach: " << strerror(errno) << std::endl;
                    exit(1);
                }
                
                std::cout << "Successfully injected infinite loop and detached\n";
                break;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <pid> <address_hex>\n";
        return 1;
    }

    pid_t pid = std::stoi(argv[1]);
    void* addr = reinterpret_cast<void*>(std::stoull(argv[2], nullptr, 16));
    int condition = 3; // read&write

    attach_process(pid);
    
    int slot = set_watchpoint(pid, addr, LENGTH_BYTE, condition);
    if (slot == -1) {
        std::cerr << "Failed to set watchpoint\n";
        return 1;
    }
    
    std::cout << "Watchpoint set at 0x" << std::hex << addr 
              << " using DR" << std::dec << slot << std::endl;
    
    debug_loop(pid, addr);

    return 0;
}