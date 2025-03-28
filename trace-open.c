#include <uapi/linux/openat2.h>
#include <linux/sched.h>
#include <linux/limits.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>

// 定义数据结构
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

// 定义性能事件映射
BPF_PERF_OUTPUT(events);

// 定义kprobe处理函数
int hello_world(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how) {
    struct data_t data = {};

    // 获取PID和时间
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();

    // 获取进程名
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        bpf_probe_read_user(&data.fname, sizeof(data.fname), filename);
    }

    // 提交性能事件
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
