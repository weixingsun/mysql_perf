#!/usr/bin/python
#
# USAGE: mysql_counter [select/insert/update/delete]
# This uses this tool, you needs enable tracing function with -DENABLE_DTRACE=1.
#
# 5-Mar-2021   Weixing.Sun@Gmail.Com

from __future__ import print_function
from bcc import BPF, USDT
from bcc.utils import printb
import sys, subprocess, time

def usage():
    print("USAGE: mysql_counter [select/insert/update/delete]")

TYPES = [ 'select', 'insert', 'update', 'delete' ]
pid = int(subprocess.check_output(['pgrep', '-n', 'mysqld']))
TYPE=""
if len(sys.argv) == 1:
    TYPE="insert"
elif (len(sys.argv) == 2) and (sys.argv[1] in TYPES):
    TYPE = sys.argv[1]
else:
    usage()
    exit()
    
debug = 0
QUERY_MAX = 128

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

#define QUERY_MAX	""" + str(QUERY_MAX) + """

//////////////////////////////////// count
struct key_t {
    char c[QUERY_MAX];
};
BPF_HASH(map_counts, struct key_t);

//////////////////////////////////// latency
struct start_t {
    u64 ts;
    char *query;
};

struct data_t {
    u64 pid;
    u64 ts;
    u64 delta;
    char query[QUERY_MAX];
};

BPF_HASH(start_tmp, u32, struct start_t);
BPF_PERF_OUTPUT(events);

int do_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct start_t start = {};
    start.ts = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &start.query);
    start_tmp.update(&pid, &start);
    return 0;
};

int do_done(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct start_t *sp;
    sp = start_tmp.lookup(&pid);
    if (sp == 0) return 0; // skip if tracing start not captured

    u64 delta = bpf_ktime_get_ns() - sp->ts;
    if (delta >= 0) {
    struct data_t data = {.pid = pid, .ts = sp->ts, .delta = delta};
    bpf_probe_read_user(&data.query, sizeof(data.query), (void *)sp->query);
    //events.perf_submit(ctx, &data, sizeof(data));
    }
    struct key_t key = {};
    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)sp->query);
    map_counts.increment(key);

    start_tmp.delete(&pid);

    return 0;
};

"""

u = USDT(pid=pid)
# query contains lots of COMMIT , so skip it
u.enable_probe(probe=TYPE+"__start", fn_name="do_start")
u.enable_probe(probe=TYPE+"__done", fn_name="do_done")
if debug:
    print(u.get_text())
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text, usdt_contexts=[u])

# header
print("Counting %s statements for MySQL %d ... Ctrl+C to End" % (TYPE,pid))
#print("%-14s %-6s %8s %s" % ("TIME(s)", "PID", "MS", "QUERY"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    print("%-14.6f %-6d %8.3f %s" % (float(event.ts - start) / 1000000000,
        event.pid, float(event.delta) / 1000000, event.query))

# loop with callback to print_event
#b["events"].open_perf_buffer(print_event, page_cnt=64)
#while 1:
#    try:
#        b.perf_buffer_poll()
#    except KeyboardInterrupt:
#        exit()
t1 = time.perf_counter_ns()
try:
    time.sleep(10000)
except KeyboardInterrupt:
    pass

t2 = time.perf_counter_ns()
total_time = (t2-t1)/1000_000_000
print("%10s %s" % ("COUNT", "SQLstatements"))
counts = b.get_table("map_counts")

total_count = 0
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    printb(b"%10d \"%s\"" % (v.value, k.c))
    total_count+=v.value

print("Captured total %d %s statements in %-8.3f" % (total_count, TYPE, total_time))
