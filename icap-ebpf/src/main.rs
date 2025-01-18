#![no_std]
#![no_main]

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, gen::bpf_probe_read_user},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::{ProbeContext, RetProbeContext},
};
// use aya_log_ebpf::info;
use icap_common::{IcapEvent, MAX_BUF_SIZE, MAX_ENTRIES};

// 定义两个映射
// 一个用于记录消息
// 一个用于发送消息
#[map]
static ICAP_SCRATCH: PerCpuArray<IcapEvent> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ICAP_EVENTS: PerfEventArray<IcapEvent> = PerfEventArray::new(0);

// 定义一个HashMap类型的映射
// 用于存放线程ID和对应的缓冲区地址
#[map]
static ICAP_BUF: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[uprobe]
pub fn ssl_rw_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_rw_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_ssl_rw_enter(ctx: ProbeContext) -> Result<u32, i64> {
    let uid: u32 = bpf_get_current_uid_gid() as u32;

    // 不关心系统应用 只关心用户程序
    if uid < 10000 {
        return Ok(0);
    }

    let buffer: *const c_void = ctx.arg(1).ok_or(1i64)?;
    let buffer_ptr = buffer as u64;
    // let number: usize = ctx.arg(2).ok_or(1i64)?;

    let pid_tgid: u64 = bpf_get_current_pid_tgid();
    // let pid: u32 = (pid_tgid >> 32) as u32;
    let tid: u32 = pid_tgid as u32;

    ICAP_BUF.insert(&tid, &buffer_ptr, 0)?;

    Ok(0)
}

#[uretprobe]
pub fn ssl_read_leave(ctx: RetProbeContext) -> u32 {
    match try_ssl_rw_leave(ctx, true) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

#[uretprobe]
pub fn ssl_write_leave(ctx: RetProbeContext) -> u32 {
    match try_ssl_rw_leave(ctx, false) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

// 读/写函数出口插桩
fn try_ssl_rw_leave(ctx: RetProbeContext, is_read: bool) -> Result<u32, i64> {
    let uid: u32 = bpf_get_current_uid_gid() as u32;

    // 不关心系统应用 只关心用户程序
    if uid < 10000 {
        return Ok(0);
    }

    // 没有数据的话直接跳过
    let len: c_int = ctx.ret().ok_or(1i64)?;
    if len <= 0 {
        return Ok(0);
    }
    let length = len as u32;

    let pid_tgid: u64 = bpf_get_current_pid_tgid();
    let pid: u32 = (pid_tgid >> 32) as u32;
    let tid: u32 = pid_tgid as u32;

    if let Some(&buffer) = unsafe { ICAP_BUF.get(&tid) } {
        // let event: *mut IcapEvent = ICAP_SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
        let event = unsafe {
            let ptr = ICAP_SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
            &mut *ptr
        };

        // let comm = bpf_get_current_comm()?;
        let buf_copy_size: u32 = if length > MAX_BUF_SIZE as u32 {
            MAX_BUF_SIZE as u32
        } else {
            length
        };

        event.pid = pid;
        event.tid = tid;
        event.uid = uid;
        event.length = length;
        event.buf_copy_size = buf_copy_size;
        event.is_read = is_read;

        // unsafe { bpf_probe_read_user(buffer as *const u8, &mut event.buffer)? };
        // 读取用户空间数据 保存到事件中
        unsafe {
            bpf_probe_read_user(
                event.buffer.as_mut_ptr() as *mut c_void,
                buf_copy_size,
                buffer as *const c_void,
            );
        }

        ICAP_EVENTS.output(&ctx, &*event, 0);
        ICAP_BUF.remove(&tid)?;
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
