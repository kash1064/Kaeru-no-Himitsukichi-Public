#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <iostream>


void ptrace_method(pid_t pid, void* addr, long new_value)
{
    // 対象プロセスにアタッチする
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1)
    {
        std::cerr << "Failed to attach: " << strerror(errno) << std::endl;
        return;
    }
    waitpid(pid, nullptr, 0);

    // 指定アドレスの値を読み込む
    long current_value = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
    std::cout << "Current value at " << addr << ": " << current_value << std::endl;

    // 指定アドレスに値を書き込む
    if (ptrace(PTRACE_POKEDATA, pid, addr, new_value) == -1)
    {
        std::cerr << "Failed to write: " << strerror(errno) << std::endl;
    }

    // 対象プロセスからデタッチする
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
}

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <pid> <address> <new_value>" << std::endl;
        return 1;
    }

    pid_t pid = std::stol(argv[1]);
    void* addr = (void*)std::stoull(argv[2], nullptr, 16);
    long new_value = std::stol(argv[3]);

    ptrace_method(pid, addr, new_value);

    return 0;
}