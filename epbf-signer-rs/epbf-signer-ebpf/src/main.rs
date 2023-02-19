#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint(name = "epbf_signer")]
pub fn epbf_signer(ctx: TracePointContext) -> u32 {
    match try_epbf_signer(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_epbf_signer(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter_bpf called");
    unsafe{
        //cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_bpf/format
        let cmd= ctx.read_at::<u8>(16).unwrap();
        info!(&ctx,"bpf cmd: {}", cmd)
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
