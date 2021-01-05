// Rust port of execsnoop.c
// See also: https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.c

use core::mem;
use core::time::Duration;
use std::env;
use std::str;

use anyhow::Result;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;

mod bpf;
use bpf::*;

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
    // let mut event: Event = Event {
    //     comm: [0; 16],
    //     pid: -1,
    //     tgid: -1,
    //     ppid: -1,
    //     uid: -1,
    //     retval: 0,
    //     args_count: 0,
    //     args_size: 0,
    //     args: [0; 60 * 128],
    // };
    let mut event: Event = Event::default();
    let event_size = mem::size_of_val(&event);

    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let comm = str::from_utf8(&event.comm).unwrap().trim_end_matches(char::from(0));
    let args: Vec<&str> = str::from_utf8(&data[event_size..]).unwrap().trim_end_matches(char::from(0)).split('\0').collect();

    println!("{:16} {:<6} {:?}", comm, event.pid, args);
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

#[allow(clippy::print_literal)]
fn main() -> Result<()> {
    let mut skel_builder: ExecsnoopSkelBuilder = ExecsnoopSkelBuilder::default();
    let mut open_skel: OpenExecsnoopSkel = skel_builder.open()?;
    if let Ok(uid) = env::var("TARGET_UID") {
        open_skel.rodata().targ_uid = uid.parse()?;
    } else {
        open_skel.rodata().targ_uid = u32::MAX;
    }
    open_skel.rodata().ignore_failed = 0;
    open_skel.rodata().max_args = 20;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("{:16} {:6} {}", "COMM", "PID", "ARGS");

    let perf = PerfBufferBuilder::new(skel.maps().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
