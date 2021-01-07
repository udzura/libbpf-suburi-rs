// Rust port of execsnoop.c
// See also: https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.c

use core::mem;
use core::time::Duration;
use std::str;
use std::convert::TryFrom;

use chrono::Local;
use anyhow::Result;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use structopt::StructOpt;

mod bpf;
use bpf::*;

#[derive(Debug, StructOpt)]
struct Command {
    /// Trace this UID only
    #[structopt(short = "u", default_value = "-1", value_name = "UID")]
    uid: i32,
    /// Include failed exec()s
    #[structopt(short = "x")]
    fails: bool,
    /// Maximum number of arguments parsed and displayed
    #[structopt(long = "max-args", default_value = "20", value_name = "MAX_ARGS")]
    max_args: i32,
}

#[repr(C)]
#[derive(Default)]
struct Event {
    pub comm: [u8; 16],
    pub pid: i32,
    pub tgid: i32,
    pub ppid: i32,
    pub uid: i32,
    pub retval: i32,
    pub args_count: i32,
    pub args_size: u32,
    //pub args: [u8; 30],
}
unsafe impl Plain for Event {}

fn handle_event(_cpu: i32, data: &[u8]) {
    let now = Local::now();
    let mut event: Event = Event::default();
    let event_size = mem::size_of_val(&event);

    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let comm = str::from_utf8(&event.comm).unwrap().trim_end_matches(char::from(0));
    let args: Vec<&str> = str::from_utf8(&data[event_size..]).unwrap().trim_end_matches(char::from(0)).split('\0').collect();

    println!(
        "{:8} {:<6} {:16} {:<6} {:<6} {:3} {:?}",
        now.format("%H:%M:%S"),
        event.uid,
        comm,
        event.pid,
        event.ppid,
        event.retval,
        args
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

#[allow(clippy::print_literal)]
fn main() -> Result<()> {
    let opts: Command = Command::from_args();

    let mut skel_builder: ExecsnoopSkelBuilder = ExecsnoopSkelBuilder::default();
    let mut open_skel: OpenExecsnoopSkel = skel_builder.open()?;
    if opts.uid >= 0 {
        let uid: u32 = TryFrom::try_from(opts.uid)?;
        open_skel.rodata().targ_uid = uid;
    } else {
        open_skel.rodata().targ_uid = u32::MAX;
    }

    if opts.fails {
        open_skel.rodata().ignore_failed = 0
    } else {
        open_skel.rodata().ignore_failed = 1
    }
    open_skel.rodata().max_args = opts.max_args;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!(
        "{:8} {:6} {:16} {:6} {:6} {:3} {:}",
        "TIME", "UID", "PCOMM", "PID", "PPID", "RET", "ARGS"
    );

    let perf = PerfBufferBuilder::new(skel.maps().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
