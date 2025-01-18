use aya::{
    maps::perf::{AsyncPerfEventArray, PerfBufferError},
    programs::UProbe,
    util::online_cpus,
};
use bytes::BytesMut;
use clap::Parser;
use tokio::task;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use icap_common::IcapEvent;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    // 这里只处理了64位库
    let lib_path = "/apex/com.android.conscrypt/lib64/libssl.so";

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/icap"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { pid } = opt;
    // SSL读写函数入口插桩
    let ssl_rw_enter: &mut UProbe = ebpf.program_mut("ssl_rw_enter").unwrap().try_into()?;
    ssl_rw_enter.load()?;
    ssl_rw_enter.attach(Some("SSL_read"), 0, lib_path, pid)?;
    ssl_rw_enter.attach(Some("SSL_write"), 0, lib_path, pid)?;

    // SSL读写函数出口插桩
    let ssl_read_leave: &mut UProbe = ebpf.program_mut("ssl_read_leave").unwrap().try_into()?;
    ssl_read_leave.load()?;
    ssl_read_leave.attach(Some("SSL_read"), 0, lib_path, pid)?;
    let ssl_write_leave: &mut UProbe = ebpf.program_mut("ssl_write_leave").unwrap().try_into()?;
    ssl_write_leave.load()?;
    ssl_write_leave.attach(Some("SSL_write"), 0, lib_path, pid)?;

    // 处理事件
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("ICAP_EVENTS").unwrap())?;
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // 为每个CPU打开一个独立缓冲区
        let mut buf = perf_array.open(cpu_id, None)?;

        // 为每个缓冲区开一个独立线程处理
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await?;

                // events.read 包含已读取的事件数量，始终小于等于 buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];

                    let ptr: *const IcapEvent = buf.as_ptr() as *const IcapEvent;
                    let data: IcapEvent = unsafe { ptr.read_unaligned() };

                    // 操作类型
                    let op_type: &str = if data.is_read { "read" } else { "write" };

                    // 如果长度超出范围的话 输出一条提示
                    let notice: String = if data.length != data.buf_copy_size {
                        format!(
                            "\n[!] length: {}, buf_copy_size: {}\n",
                            data.length, data.buf_copy_size
                        )
                    } else {
                        "\n".to_string()
                    };

                    // buffer
                    let buffer =
                        String::from_utf8_lossy(&data.buffer[..data.buf_copy_size as usize]);

                    println!(
                        "[*] SSL {}\n- uid: {}\n- pid: {}\n- tid: {}{}\n{}",
                        op_type, data.uid, data.pid, data.tid, notice, buffer
                    );
                }
            }

            Ok::<_, PerfBufferError>(())
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
