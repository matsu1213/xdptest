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
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
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
    
    if tcp_header_len < 20 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // オプションの長さ（最大40バイトに制限）
    let mut options_len = tcp_header_len - 20;
    if options_len > 40 {
        options_len = 40;
    }

    let mut tcp_options_buf = [0u8; 40];
    let opt_base_offset = EthHdr::LEN + Ipv4Hdr::LEN + 20;
    let start = ctx.data();
    let end = ctx.data_end();

    // 【最後の魔法】1バイトずつの固定ループコピー
    // Verifierは i を「0, 1, 2...」という定数として解釈するため、
    // 「パケットポインタ + 動的変数」の計算が完全に消滅します！
    for i in 0..40 {
        if i >= options_len {
            break; // 必要な分だけコピーしたら抜ける
        }
        
        // start + (定数) + 1 > end の形になり、Verifierが完璧に理解できる
        if start + opt_base_offset + i + 1 > end {
            break;
        }
        
        // 1バイトずつスタック上の配列にコピー
        tcp_options_buf[i] = unsafe { *(start as *const u8).add(opt_base_offset + i) };
    }

    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window });

    let mut options = [0u8; 32];
    let mut index = 0usize;
    let mut mss = 0u16;
    let mut wscale = 0u8;
    let mut offset = 0usize;

    // パケット(ctx.data)ではなく、コピー済みの tcp_options_buf を解析する
    // ここから先は「ただのローカル変数の処理」になるため、絶対にパケットエラーは出ません。
    for _ in 0..40 {
        if offset >= 40 || offset >= options_len { break; }
        
        let kind = unsafe { *tcp_options_buf.as_ptr().add(offset) };
        
        if index < 32 {
            unsafe { *options.as_mut_ptr().add(index) = kind; }
        }
        offset += 1;

        if kind == 0 || kind == 1 {
            index += 1;
            continue;
        } else if kind == 2 { // MSS
            if offset + 3 > 40 || offset + 3 > options_len { break; }
            let length = unsafe { *tcp_options_buf.as_ptr().add(offset) };
            if length == 4 {
                let b1 = unsafe { *tcp_options_buf.as_ptr().add(offset + 1) };
                let b2 = unsafe { *tcp_options_buf.as_ptr().add(offset + 2) };
                mss = u16::from_be_bytes([b1, b2]);
            }
            offset += length.saturating_sub(1) as usize;
        } else if kind == 3 { // WSCALE
            if offset + 2 > 40 || offset + 2 > options_len { break; }
            let length = unsafe { *tcp_options_buf.as_ptr().add(offset) };
            if length == 3 {
                wscale = unsafe { *tcp_options_buf.as_ptr().add(offset + 1) };
            }
            offset += length.saturating_sub(1) as usize;
        } else {
            if offset >= 40 || offset >= options_len { break; }
            let length = unsafe { *tcp_options_buf.as_ptr().add(offset) };
            if length == 0 { break; }
            offset += length.saturating_sub(1) as usize;
        }
        index += 1;
    }

    let ja4t = JA4T::new(window_size, options, mss, wscale);

    let mut ja4t_buf = [0u8; 64];
    let ja4t_len = ja4t.write_to(&mut ja4t_buf);
    
    let ja4t_slice = unsafe { core::slice::from_raw_parts(ja4t_buf.as_ptr(), ja4t_len) };
    let ja4t_str = unsafe { core::str::from_utf8_unchecked(ja4t_slice) };

    info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}", source_addr, dest_port, ja4t_str);

    Ok(xdp_action::XDP_PASS)
}

impl JA4T {
    fn new(window_size: u16, options: [u8; 32], mss: u16, wscale: u8) -> Self {
        Self { window_size, options, mss, wscale }
    }

    fn write_to(&self, dst: &mut [u8]) -> usize {
        let mut w = BufWriter { buf: dst, pos: 0 };

        w.push_num(self.window_size);
        w.push(b'_');

        let mut first = true;
        for i in 0..32 {
            let opt = self.options[i];
            if opt == 0 { break; }
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

        w.pos
    }
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl BufWriter<'_> {
    #[inline(always)]
    fn push(&mut self, b: u8) {
        if self.pos < self.buf.len() {
            unsafe {
                *self.buf.as_mut_ptr().add(self.pos) = b;
            }
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
        while n > 0 && i > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        
        for j in i..5 {
            self.push(tmp[j]);
        }
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