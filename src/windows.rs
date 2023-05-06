use std::{
  collections::VecDeque,
  io::{ErrorKind, Write},
  net::Ipv4Addr,
  path::{Path, PathBuf},
  sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc,
  },
  thread::JoinHandle,
};

#[cfg(target_arch = "x86_64")]
pub const WINTUN_DLL: &'static [u8] = include_bytes!("wintun/bin/amd64/wintun.dll");
#[cfg(target_arch = "x86")]
pub const WINTUN_DLL: &'static [u8] = include_bytes!("wintun/bin/x86/wintun.dll");
#[cfg(target_arch = "arm")]
pub const WINTUN_DLL: &'static [u8] = include_bytes!("wintun/bin/arm/wintun.dll");
#[cfg(target_arch = "aarch64")]
pub const WINTUN_DLL: &'static [u8] = include_bytes!("wintun/bin/arm64/wintun.dll");

pub fn unpack_dll(path: impl AsRef<Path>) -> std::io::Result<()> {
  let mut file = std::fs::File::options()
    .write(true)
    .create(true)
    .open(path)?;
  file.write_all(WINTUN_DLL)?;
  Ok(())
}

pub fn load_wintun_with_path(path: impl AsRef<Path>) -> std::io::Result<Wintun> {
  let path = path.as_ref();
  unpack_dll(path)?;
  unsafe { wintun::load_from_path(path) }
    .map_err(|err| std::io::Error::new(ErrorKind::InvalidData, err))
}

pub const ALOGNSIDE_PATH: &'static str = "./wintun.dll";
pub fn get_tmp_path() -> PathBuf {
  let path = std::env::var_os("Temp").expect("Temp directory env variable not found");
  let path = Path::new(&path).join("wintun");
  std::fs::create_dir_all(&path).expect("Failed to create directory for wintun dll");
  path.join("wintun.dll")
}

pub fn adapter_with_path(
  path: impl AsRef<Path>,
  name: impl AsRef<str>,
  pool: impl AsRef<str>,
) -> std::io::Result<Arc<Adapter>> {
  let wintun = load_wintun_with_path(path)?;
  let name = name.as_ref();
  let pool = pool.as_ref();
  Ok(match Adapter::open(&wintun, name) {
    Ok(a) => a,
    Err(_) => {
      //If loading failed (most likely it didn't exist), create a new one
      wintun::Adapter::create(&wintun, pool, name, None)
        .map_err(|err| std::io::Error::new(ErrorKind::Other, format!("{err}")))?
    }
  })
}

pub fn session_with_path(
  path: impl AsRef<Path>,
  name: impl AsRef<str>,
  pool: impl AsRef<str>,
) -> std::io::Result<(Arc<Session>, Arc<Adapter>)> {
  let adapter = adapter_with_path(path, name, pool)?;
  let session = adapter
    .start_session(wintun::MAX_RING_CAPACITY)
    .map_err(|err| std::io::Error::new(ErrorKind::Other, format!("{err}")))?;
  Ok((Arc::new(session), adapter))
}

pub fn set_ip_address(
  adapter: &Arc<Adapter>,
  internal_ip: Ipv4Addr,
  mask: u8,
) -> std::io::Result<()> {
  let mut address_row = winapi::shared::netioapi::MIB_UNICASTIPADDRESS_ROW::default();
  unsafe {
    winapi::shared::netioapi::InitializeUnicastIpAddressEntry(&mut address_row as *mut _);
  }
  const IP_SUFFIX_ORIGIN_DHCP: winapi::shared::nldef::NL_SUFFIX_ORIGIN = 3;
  const IP_PREFIX_ORIGIN_DHCP: winapi::shared::nldef::NL_PREFIX_ORIGIN = 3;
  address_row.SuffixOrigin = IP_SUFFIX_ORIGIN_DHCP;
  address_row.PrefixOrigin = IP_PREFIX_ORIGIN_DHCP;
  const LIFETIME_INFINITE: winapi::ctypes::c_ulong = 0xffffffff;
  address_row.ValidLifetime = LIFETIME_INFINITE;
  address_row.PreferredLifetime = LIFETIME_INFINITE;
  address_row.InterfaceLuid = winapi::shared::ifdef::NET_LUID_LH {
    Value: adapter.get_luid(),
  };
  unsafe {
    let ipv4 = address_row.Address.Ipv4_mut();
    ipv4.sin_family = winapi::shared::ws2def::AF_INET as _;
    *ipv4.sin_addr.S_un.S_addr_mut() = u32::from_ne_bytes(internal_ip.octets());
  }
  address_row.OnLinkPrefixLength = mask;
  address_row.DadState = winapi::shared::nldef::IpDadStatePreferred;
  let error =
    unsafe { winapi::shared::netioapi::CreateUnicastIpAddressEntry(&mut address_row as *mut _) };
  if error != winapi::shared::winerror::ERROR_SUCCESS {
    return Err(std::io::Error::new(
      ErrorKind::AddrNotAvailable,
      format!(
        "Failed to set IP address: {:?}",
        get_last_error::Win32Error::new(error)
      ),
    ));
  }
  Ok(())
}

use wintun::{Adapter, Session, Wintun};

pub struct Tun {
  session: Arc<Session>,
  adapter: Arc<Adapter>,
  in_tx: Option<Sender<Vec<u8>>>,
  out_rx: Option<Receiver<Vec<u8>>>,
  thread: Option<JoinHandle<std::io::Result<()>>>,
  terminate: Arc<AtomicBool>,
}

pub struct TunSender {
  tx: Sender<Vec<u8>>,
}

impl TunSender {
  pub fn send(&self, packet: Vec<u8>) {
    drop(self.tx.send(packet));
  }
}

impl Tun {
  pub fn from_adapter(adapter: Arc<Adapter>) -> std::io::Result<Self> {
    let session = adapter
      .start_session(wintun::MAX_RING_CAPACITY)
      .map_err(|err| std::io::Error::new(ErrorKind::Other, format!("{err}")))?;
    let session = Arc::new(session);
    Ok(Self {
      session,
      adapter,
      in_tx: None,
      out_rx: None,
      thread: None,
      terminate: Arc::new(AtomicBool::new(true)),
    })
  }
  pub fn new_with_path(
    path: impl AsRef<Path>,
    name: impl AsRef<str>,
    pool: impl AsRef<str>,
    ip: Ipv4Addr,
    mask: u8,
  ) -> std::io::Result<Self> {
    let (session, adapter) = session_with_path(path, name, pool)?;
    set_ip_address(&adapter, ip, mask)?;
    Ok(Self {
      session,
      adapter,
      in_tx: None,
      out_rx: None,
      thread: None,
      terminate: Arc::new(AtomicBool::new(true)),
    })
  }
  pub fn new(
    name: impl AsRef<str>,
    pool: impl AsRef<str>,
    ip: Ipv4Addr,
    mask: u8,
  ) -> std::io::Result<Self> {
    Self::new_with_path(get_tmp_path(), name, pool, ip, mask)
  }
  pub fn new_alongside(
    name: impl AsRef<str>,
    pool: impl AsRef<str>,
    ip: Ipv4Addr,
    mask: u8,
  ) -> std::io::Result<Self> {
    Self::new_with_path(ALOGNSIDE_PATH, name, pool, ip, mask)
  }
  pub fn recv(&self) -> Option<Vec<u8>> {
    self.out_rx.as_ref().unwrap().try_recv().ok()
  }
  pub fn iter(&self) -> mpsc::TryIter<Vec<u8>> {
    self.out_rx.as_ref().unwrap().try_iter()
  }
  pub fn send(&self, packet: Vec<u8>) {
    drop(self.in_tx.as_ref().unwrap().send(packet));
  }
  pub fn is_registered(&self) -> bool {
    !self.terminate.load(Ordering::Relaxed)
  }
  pub fn sender(&self) -> TunSender {
    TunSender {
      tx: self.in_tx.as_ref().unwrap().clone(),
    }
  }
  pub fn adapter(&self) -> &Arc<Adapter> {
    &self.adapter
  }
}

impl Drop for Tun {
  fn drop(&mut self) {
    self.terminate.store(true, Ordering::Relaxed);
    if let Some(thread) = std::mem::replace(&mut self.thread, None) {
      drop(thread.join());
    }
    self.session.shutdown();
  }
}

impl mio::event::Source for Tun {
  fn register(
    &mut self,
    registry: &mio::Registry,
    token: mio::Token,
    interests: mio::Interest,
  ) -> std::io::Result<()> {
    self.terminate.store(false, Ordering::Relaxed);
    let waker = mio::Waker::new(registry, token)?;
    let (in_tx, in_rx) = mpsc::channel();
    let (out_tx, out_rx) = mpsc::channel();
    self.in_tx.replace(in_tx);
    self.out_rx.replace(out_rx);
    let session = Arc::clone(&self.session);
    let terminate = Arc::clone(&self.terminate);
    self.thread = Some(std::thread::spawn(move || {
      let mut packet_buffer = VecDeque::new();
      loop {
        if terminate.load(Ordering::Relaxed) {
          return Ok(());
        }
        if let Some(packet) = session.try_receive().map_err(|_| {
          std::io::Error::new(
            ErrorKind::ConnectionAborted,
            "Failed to receive packet from session",
          )
        })? {
          out_tx
            .send(packet.bytes().to_vec())
            .map_err(|err| std::io::Error::new(ErrorKind::ConnectionAborted, err))?;
          if interests.is_readable() {
            waker.wake()?;
          }
        }
        for packet in in_rx.try_iter() {
          if packet.len() > 0xFFFF {
            continue;
          }
          if let Ok(mut packet_send) = session.allocate_send_packet(packet.len() as u16) {
            packet_send.bytes_mut().copy_from_slice(&packet);
            session.send_packet(packet_send);
            drop(out_tx.send(packet));
            if interests.is_readable() {
              waker.wake()?;
            }
          } else {
            packet_buffer.push_back(packet);
          }
        }
        if let Some(packet) = packet_buffer.pop_front() {
          if let Ok(mut packet_send) = session.allocate_send_packet(packet.len() as u16) {
            packet_send.bytes_mut().copy_from_slice(&packet);
            session.send_packet(packet_send);
          } else {
            packet_buffer.push_back(packet);
          }
        }
        if interests.is_writable() && packet_buffer.is_empty() {
          waker.wake()?;
        }
      }
    }));
    Ok(())
  }

  fn reregister(
    &mut self,
    registry: &mio::Registry,
    token: mio::Token,
    interests: mio::Interest,
  ) -> std::io::Result<()> {
    self.deregister(registry)?;
    self.register(registry, token, interests)
  }

  fn deregister(&mut self, _: &mio::Registry) -> std::io::Result<()> {
    self.terminate.store(true, Ordering::Relaxed);
    std::mem::replace(&mut self.thread, None)
      .ok_or(std::io::Error::new(
        ErrorKind::Other,
        "Failed precondition: not registered yet",
      ))?
      .join()
      .unwrap()
  }
}
