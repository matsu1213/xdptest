#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr
};

struct JA4T {
    window_size: u16,
    options: [u8; 8],
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
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let is_initial_syn = unsafe { (*tcphdr).syn() != 0 && (*tcphdr).ack() == 0 };
    
    if !is_initial_syn {
        return Ok(xdp_action::XDP_PASS);
    }

    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    let doff = unsafe { (*tcphdr).doff() }; 
    let tcp_header_len = (doff as usize) * 4;
    
    if tcp_header_len < 20 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let max_options_len = (tcp_header_len.saturating_sub(20)) & 0x3F;
    let opt_base_offset = EthHdr::LEN + Ipv4Hdr::LEN + 20;

    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window });

    let mut options = [255u8; 8];
    let mut opt_idx = 0usize;
    let mut mss = 0u16;
    let mut wscale = 0u8;
    let mut offset = 0usize;

    let start = ctx.data();
    let end = ctx.data_end();

    for _ in 0..8 {
        offset &= 0x3F; 
        if offset >= max_options_len { break; }
        
        let curr_ptr = start + opt_base_offset + offset;
        if curr_ptr + 1 > end { break; }
        
        // 【重要1】read_volatile で LLVMのポインタ結合最適化を強制ブロック
        let kind = unsafe { core::ptr::read_volatile(curr_ptr as *const u8) };
        
        let safe_idx = opt_idx & 0x07;
        options[safe_idx] = kind;
        opt_idx += 1;
        
        if kind == 0 { break; } 
        if kind == 1 { 
            offset += 1; 
            continue; 
        }
        
        if curr_ptr + 2 > end { break; }
        let opt_len = unsafe { core::ptr::read_volatile((curr_ptr + 1) as *const u8) };
        
        if opt_len < 2 { break; }
        
        if kind == 2 && opt_len == 4 {
            if curr_ptr + 4 <= end {
                // ここも1バイトずつ確実に読ませる
                let b1 = unsafe { core::ptr::read_volatile((curr_ptr + 2) as *const u8) };
                let b2 = unsafe { core::ptr::read_volatile((curr_ptr + 3) as *const u8) };
                mss = u16::from_be_bytes([b1, b2]);
            }
        } else if kind == 3 && opt_len == 3 {
            if curr_ptr + 3 <= end {
                wscale = unsafe { core::ptr::read_volatile((curr_ptr + 2) as *const u8) };
            }
        }
        
        offset += opt_len as usize;
    }

    let ja4t = JA4T { window_size, options, mss, wscale };
    
    // 【重要2】スライス渡しをやめ、配列を直接返す形に変更（ファットポインタ回避）
    let (ja4t_buf, ja4t_len) = ja4t.to_bytes();
    
    let final_len = ja4t_len & 0x3F;
    let ja4t_slice = unsafe { core::slice::from_raw_parts(ja4t_buf.as_ptr(), final_len) };
    let ja4t_str = unsafe { core::str::from_utf8_unchecked(ja4t_slice) };

    info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}", source_addr, dest_port, ja4t_str);

    Ok(xdp_action::XDP_PASS)
}

impl JA4T {
    // スライス引数 (&mut [u8]) を消去し、完成した配列と長さを返す
    fn to_bytes(&self) -> ([u8; 64], usize) {
        let mut w = BufWriter::new();

        w.push_num(self.window_size);
        w.push(b'_');

        let mut first = true;
        for i in 0..8 {
            let opt = self.options[i];
            if opt == 255 { break; }
            if !first {
                w.push(b'-');
            }
            first = false;
            w.push_num(opt as u16);
        }

        w.push(b'_');
        w.push_num(self.mss);
        w.push(b'_');
        w.push_num(self.wscale as u16);

        (w.buf, w.pos)
    }
}

// 参照を持たず、メモリをすべて所有する形に変更
struct BufWriter {
    buf: [u8; 64],
    pos: usize,
}

impl BufWriter {
    #[inline(always)]
    fn new() -> Self {
        Self { buf: [0; 64], pos: 0 }
    }

    #[inline(always)]
    fn push(&mut self, b: u8) {
        if self.pos < 64 {
            // 安全な配列アクセスに戻す
            self.buf[self.pos] = b;
            self.pos += 1;
        }
    }

    #[inline(always)]
    fn push_num(&mut self, mut n: u16) {
        if n == 0 {
            self.push(b'0');
            return;
        }
        let mut tmp = [0u8; 5]; 
        let mut i = 5;
        
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        
        if i <= 0 { self.push(tmp[0]); }
        if i <= 1 { self.push(tmp[1]); }
        if i <= 2 { self.push(tmp[2]); }
        if i <= 3 { self.push(tmp[3]); }
        if i <= 4 { self.push(tmp[4]); }
    }
}

#[inline(always)]
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