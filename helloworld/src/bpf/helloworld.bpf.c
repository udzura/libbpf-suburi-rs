#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
  __u32 pid;
  char msg[32];
};

const volatile bool espanol = false;

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint__syscalls__sys_enter_clone(void* ctx)
{
  const char msg[] = "Hello World!";
  const char msg_es[] = "¡Hola Mundo!";

  struct event event = {};
  u32 pid = bpf_get_current_pid_tgid();
  event.pid = pid;
  if (espanol)
    bpf_probe_read_user_str(&event.msg, sizeof(event.msg), msg_es);
  else
    bpf_probe_read_user_str(&event.msg, sizeof(event.msg), msg);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                        &event, sizeof(event));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
