let install_signalhandle = null;

const prctl_ptr = Module.findExportByName(null, 'prctl')
const sigfillset_ptr = Module.findExportByName(null, 'sigfillset')
const sigaction_ptr = Module.findExportByName(null, 'sigaction')
const __android_log_print_ptr = Module.findExportByName(null, '__android_log_print')
const syscall_ptr = Module.findExportByName(null, 'syscall')
const android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");

function init(){
    install_signalhandle = new NativeFunction(cm.install_signalhandle, "void", [])
    install_signalhandle();
}

function hook_dlopen(){
    var path = null;
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function(args) {
            if (install_signalhandle == null) {
                init()
            }
        },onLeave(ret){

        }
    });
}

// CModule模块编写
const cm = new CModule(`
#include <stdio.h>
#include <gum/gumprocess.h>

// define the target_nr
#define target_nr 56

// syscall again with args[SECMAGIC_POS] SEC_MAGIC avoid infinite loop
#define SECMAGIC 0xdeadbeef
#define SECMAGIC_POS 3

// test syscall no
#define __NR_openat 56
#define __NR_mincore 232

#define BPF_STMT(code,k) { (unsigned short) (code), 0, 0, k }
#define BPF_JUMP(code,k,jt,jf) { (unsigned short) (code), jt, jf, k }
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JEQ 0x10
#define BPF_JMP 0x05
#define BPF_K 0x00
#define BPF_RET 0x06

#define PR_SET_SECCOMP	22
#define PR_SET_NO_NEW_PRIVS	38
#define SECCOMP_MODE_FILTER	2
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

#define SIGSYS 31
#define SIG_UNBLOCK     2
#define __user
#define SI_MAX_SIZE 128
#define SA_SIGINFO 0x00000004

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long sigset_t;
typedef sigset_t sigset64_t;
typedef unsigned long __kernel_size_t;

extern int __android_log_print(int prio, const char* tag, const char* fmt, ...);
extern void *malloc(size_t __byte_count);
extern long syscall(long __number, ...);
extern void on_message(const gchar *message);
extern int prctl(int __option, ...);
extern int sigfillset(sigset_t* __set);
extern int sigaction(int __signal, const struct sigaction* __new_action, struct sigaction* __old_action);
int install_filter();
#define log(...) __android_log_print(3, "native", __VA_ARGS__)

// seccomp filter
struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

struct sock_filter {
    __u16 code;
    __u8 jt;
    __u8 jf;
    __u32 k;
};

struct sock_fprog {
    unsigned short len;
    struct sock_filter * filter;
};

// sigaction
union __sifields {
    struct {
        void __user * _call_addr;
        int _syscall;
        unsigned int _arch;
    } _sigsys;
};

#define __SIGINFO struct { int si_signo; int si_errno; int si_code; union __sifields _sifields; }

typedef struct siginfo {
    union {
      __SIGINFO;
      int _si_pad[SI_MAX_SIZE / sizeof(int)];
    };
} siginfo_t;

typedef void (*sighandler_t)(int);

struct sigaction { 
    int sa_flags;
    union {
      sighandler_t sa_handler;
      void (*sa_sigaction)(int, struct siginfo*, void*);
    };
    sigset_t sa_mask;
    void (*sa_restorer)(void);
};

typedef struct sigaltstack {
    void * ss_sp;
    int ss_flags;
    __kernel_size_t ss_size;
} stack_t;


struct sigcontext {
	__u64 fault_address;
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
	__u8 __reserved[4096] __attribute__((__aligned__(16)));
};

typedef struct sigcontext mcontext_t;

typedef struct ucontext {
    unsigned long uc_flags;
    struct ucontext *uc_link;
    stack_t uc_stack;
    union {
      sigset_t uc_sigmask;
      sigset64_t uc_sigmask64;
    };
    /* The kernel adds extra padding after uc_sigmask to match glibc sigset_t on ARM64. */
    char __padding[128 - sizeof(sigset_t)];
    mcontext_t uc_mcontext;
} ucontext_t;



void sig_handler(int signo, siginfo_t *info, void *data) {
    int my_signo = info->si_signo;
    // log("my_signo: %d", my_signo);
    unsigned long sysno = ((ucontext_t *) data)->uc_mcontext.regs[8];
    unsigned long arg0 = ((ucontext_t *) data)->uc_mcontext.regs[0];
    unsigned long arg1 = ((ucontext_t *) data)->uc_mcontext.regs[1];
    unsigned long arg2 = ((ucontext_t *) data)->uc_mcontext.regs[2];

    int fd, mincore_ret;

    switch (sysno) {
        log("sysno: %d", sysno);
        case __NR_openat:
            // syscall with args[3] SEC_MAGIC avoid infinite loop
            fd = syscall(__NR_openat, arg0, arg1, arg2, SECMAGIC);
            log("[Openat 56] filename: %s", (char *) arg1);
            ((ucontext_t *) data)->uc_mcontext.regs[0] = fd;
            log("[Openat 56] ret fd: %d", fd);
            break;
        case __NR_mincore:
            mincore_ret = syscall(__NR_mincore, arg0, arg1, arg2, SECMAGIC);
            log("[mincore 232] args: %lx %d %lx", arg0, arg1, arg2);
            log("[mincore 232] orig args[2] : %lld", *(char *)arg2);
            *((int *)arg2 + 0) = 0x0;
            ((ucontext_t *) data)->uc_mcontext.regs[0] = mincore_ret;
            log("[mincore 232] changed args[2] : %d", *(int *)arg2);
            break;
        default:
            break;
    }
}

void install_signalhandle(){
    struct sigaction sa;
    sigset_t sigset;

    sigfillset(&sigset);

    sa.sa_sigaction = sig_handler;
    sa.sa_mask = sigset;
    sa.sa_flags = SA_SIGINFO;
    install_filter();
    if (sigaction(SIGSYS, &sa, NULL) == -1) {
        log("sigaction init failed.\n");
        return ;
    }

    log("sigaction init success.\n");
}

int install_filter() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, target_nr, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[SECMAGIC_POS])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP)
    };
    struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        on_message("prctl(NO_NEW_PRIVS)");
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        on_message("prctl(PR_SET_SECCOMP)");
        return 1;
    }
    return 0;
}

`, {
    prctl: prctl_ptr,
    __android_log_print: __android_log_print_ptr,
    syscall: syscall_ptr,
    sigfillset: sigfillset_ptr,
    sigaction: sigaction_ptr,
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        console.log(message)
    }, 'void', ['pointer'])
});

setImmediate(hook_dlopen)
