#![no_std]

pub const MAX_ENTRIES: u32 = 1024;

// 获取缓冲区的最大值 超出部分暂时不对其进行处理
pub const MAX_BUF_SIZE: usize = 4096;

// 定义消息的结构体
#[repr(C)]
pub struct IcapEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    // pub command: [u8; 16],
    pub buffer: [u8; MAX_BUF_SIZE],
    pub length: u32,
    pub buf_copy_size: u32,
    pub is_read: bool,
}
