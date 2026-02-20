#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::{SO_RCVLOWAT, xdp_action}, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr
};

struct JA4T {
    window_size: u16,
    options: [u8; 32],
    mss: u16,
    wscale: u8
}

#[xdp]
pub fn xdptest(ctx: XdpContext) -> u32 {
    match try_xdptest(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdptest(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // (2)
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    let is_initial_syn = unsafe { (*tcphdr).syn() != 0 && (*tcphdr).ack() == 0 };
    
    if !is_initial_syn {
        return Ok(xdp_action::XDP_PASS);
    }

    let doff = unsafe { (*tcphdr).doff() }; 
    let tcp_header_len = (doff as usize) * 4;

    let mut offset = EthHdr::LEN + Ipv4Hdr::LEN + 20;
    let options_end = EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len;

    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window});

    let mut options = [0u8; 32];
    let mut index = 0usize;
    let mut mss = 0u16;
    let mut wscale = 0u8;

    while offset < options_end {
        let kind = unsafe { *(ctx.data() as *const u8).add(offset) };
        if index < options.len() {
            options[index] = kind;
        }
        offset += 1;

        if kind == 0 {
            continue; // End of Option List, but we will continue to check if there are more options.
        } else if kind == 1 {
            continue;
        } else if kind == 2 {
            // MSS Option
            if offset + 3 > options_end {
                continue; // Not enough space for MSS option
            }
            let length = unsafe { *(ctx.data() as *const u8).add(offset) };
            if length != 4 {
                continue; // Invalid MSS option length
            }
            mss = u16::from_be_bytes([
                unsafe { *(ctx.data() as *const u8).add(offset + 1) },
                unsafe { *(ctx.data() as *const u8).add(offset + 2) },
            ]);
            offset += 3; // Move past MSS option
        } else if kind == 3 {
            // WSCALE Option
            if offset + 2 > options_end {
                continue; // Not enough space for WSCALE option
            }
            let length = unsafe { *(ctx.data() as *const u8).add(offset) };
            if length != 3 {
                continue; // Invalid WSCALE option length
            }
            wscale = unsafe { *(ctx.data() as *const u8).add(offset + 1) };
            offset += 2; // Move past WSCALE option
        }
        index += 1;
    }

    let ja4t = JA4T::new(window_size, options, mss, wscale);

    // (3) build JA4T ascii into fixed buffer and log
    let mut ja4t_buf = [0u8; 64];
    let ja4t_len = ja4t.write_to(&mut ja4t_buf);
    let ja4t_str = unsafe { core::str::from_utf8_unchecked(&ja4t_buf[..ja4t_len]) };

    info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}", source_addr, dest_port, ja4t_str);

    Ok(xdp_action::XDP_PASS)
}

impl JA4T {
    fn new(window_size: u16, options: [u8; 32], mss: u16, wscale: u8) -> Self {
        Self { window_size, options, mss, wscale }
    }

    // Write JA4T into the provided buffer in the format:
    // Example: 65535_2-4-8-1-3_1460_7
    // Returns number of bytes written.
    fn write_to(&self, dst: &mut [u8]) -> usize {
        let mut w = BufWriter { buf: dst, pos: 0 };

        // window_size
        w.push_num(self.window_size as u64);
        w.push(b'_');

        // options list (sep by '-')
        let mut first = true;
        for &opt in &self.options {
            if opt == 0 { break; }
            if !first {
                w.push(b'-');
            }
            first = false;
            w.push_num(opt as u64);
        }

        w.push(b'_');
        
        // mss
        w.push_num(self.mss as u64);
        w.push(b'_');
        
        // wscale
        w.push_num(self.wscale as u64);

        w.pos
    }
}

// バッファへの書き込みと境界チェックを一元管理するヘルパー
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl BufWriter<'_> {
    // 1バイトだけ書き込む
    #[inline]
    fn push(&mut self, b: u8) {
        if self.pos < self.buf.len() {
            self.buf[self.pos] = b;
            self.pos += 1;
        }
    }

    // スライス（複数バイト）を安全に書き込む
    #[inline]
    fn push_bytes(&mut self, bytes: &[u8]) {
        let remain = self.buf.len() - self.pos;
        let len = core::cmp::min(remain, bytes.len());
        self.buf[self.pos..self.pos + len].copy_from_slice(&bytes[..len]);
        self.pos += len;
    }

    // u64数値をアスキー文字列として書き込む
    fn push_num(&mut self, mut n: u64) {
        if n == 0 {
            self.push(b'0');
            return;
        }
        
        // u64の最大文字数は20桁なので、バッファを確保して後ろから詰める
        let mut tmp = [0u8; 20];
        let mut i = 20;
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        
        // 完成した文字列部分をまとめて書き込み
        self.push_bytes(&tmp[i..]);
    }
}

#[inline(always)] // (1)
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
