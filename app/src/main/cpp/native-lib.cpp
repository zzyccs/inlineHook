#include <jni.h>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <cstring>
#include <android/log.h>

#define LOG_TAG "DEBUG"
void LOGD(int lvl, const char* log, ...)
{
    va_list arg;
    va_start(arg, log);
    __android_log_vprint(lvl, LOG_TAG, log, arg);
    va_end(arg);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_cs_inline_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* thisobj */,
        jstring jstr) {
    std::string hello = "Hello from C++: ";
    hello.append(env->GetStringUTFChars(jstr, nullptr));
    return env->NewStringUTF(hello.c_str());
}

//******************************************************************************************************************
u_long thread_local ori_lr = 0;
u_long off_shellcode_part2_ = 0;

void on_enter_1(u_long sp)
{
    //sp回到初始位置
    sp = sp + 0x60;
    u_long lr = *(u_long*)(sp - 8);
    u_long lr_ptr = sp - 8;
    u_long pc = *(u_long*)(sp - 0x20);
    pc -= 0x20;
    ori_lr = lr;
    //一般来说8个参数顶天了
    u_long arg1 = *(u_long*)(sp - 0x28);
    u_long arg2 = *(u_long*)(sp - 0x30);
    u_long arg3 = *(u_long*)(sp - 0x38);
    u_long* arg3_ptr = (u_long*)(sp - 0x38);
    u_long arg4 = *(u_long*)(sp - 0x40);
    u_long arg5 = *(u_long*)(sp - 0x48);
    u_long arg6 = *(u_long*)(sp - 0x50);
    u_long arg7 = *(u_long*)(sp - 0x58);
    u_long arg8 = *(u_long*)(sp - 0x60);
    //sp上还有参数的话照下面这么写
    u_long arg9 = *(u_long*)(sp);
    u_long arg10 = *(u_long*)(sp + 0x8);

    //打印String参数
    JNIEnv* env = reinterpret_cast<JNIEnv *>(arg1);
    jstring jstr = reinterpret_cast<jstring>(arg3);
    LOGD(ANDROID_LOG_INFO, "[+] arg3: %s", env->GetStringUTFChars(jstr, nullptr));
    //替换String参数
    jstring jstr_new = env->NewStringUTF("--This is on_enter_1 !");
    *arg3_ptr = reinterpret_cast<u_long>(jstr_new);

    //修改LR寄存器，保证原始函数执行完毕会回到on_leave_1函数
    *(u_long*)lr_ptr = pc + off_shellcode_part2_;
    LOGD(ANDROID_LOG_WARN, "[+] on_enter_1: %p", on_enter_1);
}

void on_leave_1(u_long sp)
{
    //sp回到初始位置
    sp = sp + 0x10;
    u_long x0 = *(u_long*)(sp - 8);
    u_long* x0_ptr = (u_long*)(sp - 8);
    u_long lr = *(u_long*)(sp - 0x10);
    u_long* lr_ptr = (u_long*)(sp - 0x10);

    // do_something ...

    *(u_long*)lr_ptr = ori_lr;
    LOGD(ANDROID_LOG_DEBUG, "[+] on_leave_1: %p", on_leave_1);
}

// Hook函数开头指令，并托管执行
extern "C" JNIEXPORT void JNICALL
Java_com_cs_inline_MainActivity_inlineHook1(JNIEnv* env,
                                            jobject /* thisobj */)
{
    u_long func_addr = (u_long)Java_com_cs_inline_MainActivity_stringFromJNI;
    extern u_long _shellcode_start_, _the_func_addr_, _end_func_addr_, _ori_ins_set1_, _retback_addr_, _shellcode_end_, _trampoline_, _jmp_addr_, _shellcode_part2_;
    u_long total_len = (u_long)&_shellcode_end_ - (u_long)&_shellcode_start_;
    LOGD(ANDROID_LOG_DEBUG, "[+] ShellCode len: %d, target func: %p", total_len, func_addr);

    u_long page_size = getpagesize();
    u_long shellcode_mem_start = (u_long)mmap(0, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    memset((void *)shellcode_mem_start, 0, page_size);
    memcpy((void *)shellcode_mem_start, (void *)&_shellcode_start_, total_len);
    LOGD(ANDROID_LOG_DEBUG, "[+] shellcode_mem_start: %p", shellcode_mem_start);

    *(u_long*)&_jmp_addr_ = shellcode_mem_start;

    u_long mem_the_func_addr_ = (u_long)&_the_func_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_end_func_addr_ = (u_long)&_end_func_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_ori_ins_set1_ = (u_long)&_ori_ins_set1_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_retback_addr_ = (u_long)&_retback_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    if(!off_shellcode_part2_)
        off_shellcode_part2_ = (u_long)&_shellcode_part2_ - (u_long)&_shellcode_start_;

    *(u_long*)mem_the_func_addr_ = (u_long)on_enter_1;
    *(u_long*)mem_end_func_addr_ = (u_long)on_leave_1;
    *(u_long*)mem_retback_addr_ = (u_long)func_addr + 0x10;

    *(u_long*)mem_ori_ins_set1_ = *(u_long*)func_addr;
    *(u_long*)(mem_ori_ins_set1_ + 8) = *(u_long*)(func_addr + 8);

    u_long entry_page_start = (u_long)(func_addr) & (~(page_size-1));
    mprotect((u_long*)entry_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    *(u_long*)func_addr = *(u_long*)&_trampoline_;
    *(u_long*)(func_addr + 8) = *(u_long*)(((u_long)&_trampoline_) + 8);
//    clearcache((char *)(func_addr - 0x20), (char *)(func_addr + 0x20));
}

void on_enter_2(u_long sp)
{
    //sp回到初始位置
    sp = sp + 0x60;
    u_long lr = *(u_long*)(sp - 8);
    u_long lr_ptr = sp - 8;
    u_long pc = *(u_long*)(sp - 0x20);
    pc -= 0x20;
    //一般来说jni调用8个参数顶天了
    u_long arg1 = *(u_long*)(sp - 0x28);
    u_long* arg1_ptr = (u_long*)(sp - 0x28);
    u_long arg2 = *(u_long*)(sp - 0x30);
    u_long arg3 = *(u_long*)(sp - 0x38);
    u_long arg4 = *(u_long*)(sp - 0x40);
    u_long arg5 = *(u_long*)(sp - 0x48);
    u_long arg6 = *(u_long*)(sp - 0x50);
    u_long arg7 = *(u_long*)(sp - 0x58);
    u_long arg8 = *(u_long*)(sp - 0x60);
    //sp上还有参数的话照下面这么写
    u_long arg9 = *(u_long*)(sp);
    u_long arg10 = *(u_long*)(sp + 0x8);

    LOGD(ANDROID_LOG_WARN, "[+] on_enter_2: %p", on_enter_2);
    //修改x0寄存器
    *arg1_ptr = (u_long)" ++ This is on_enter_2 !";
}

// Hook函数中间指令
extern "C" JNIEXPORT void JNICALL
Java_com_cs_inline_MainActivity_inlineHook2(JNIEnv* env,
                                            jobject /* thisobj */)
{
    u_long func_addr = (u_long)Java_com_cs_inline_MainActivity_stringFromJNI + 0x70;
    extern u_long _shellcode_start_, _the_func_addr_, _end_func_addr_, _ori_ins_set1_, _retback_addr_, _shellcode_end_, _trampoline_, _jmp_addr_, _shellcode_part2_;
    u_long total_len = (u_long)&_shellcode_end_ - (u_long)&_shellcode_start_;
    LOGD(ANDROID_LOG_DEBUG, "[+] ShellCode len: %d, target func: %p", total_len, func_addr);

    u_long page_size = getpagesize();
    u_long shellcode_mem_start = (u_long)mmap(0, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    memset((void *)shellcode_mem_start, 0, page_size);
    memcpy((void *)shellcode_mem_start, (void *)&_shellcode_start_, total_len);
    LOGD(ANDROID_LOG_DEBUG, "[+] shellcode_mem_start: %p", shellcode_mem_start);

    *(u_long*)&_jmp_addr_ = shellcode_mem_start;

    u_long mem_the_func_addr_ = (u_long)&_the_func_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_end_func_addr_ = (u_long)&_end_func_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_ori_ins_set1_ = (u_long)&_ori_ins_set1_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_retback_addr_ = (u_long)&_retback_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    if(!off_shellcode_part2_)
        off_shellcode_part2_ = (u_long)&_shellcode_part2_ - (u_long)&_shellcode_start_;

    *(u_long*)mem_the_func_addr_ = (u_long)on_enter_2;
    *(u_long*)mem_end_func_addr_ = (u_long)0;
    *(u_long*)mem_retback_addr_ = (u_long)func_addr + 0x10;

    *(u_long*)mem_ori_ins_set1_ = *(u_long*)func_addr;
    *(u_long*)(mem_ori_ins_set1_ + 8) = *(u_long*)(func_addr + 8);

    u_long entry_page_start = (u_long)(func_addr) & (~(page_size-1));
    mprotect((u_long*)entry_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    *(u_long*)func_addr = *(u_long*)&_trampoline_;
    *(u_long*)(func_addr + 8) = *(u_long*)(((u_long)&_trampoline_) + 8);
}
