use std::{
  io::{ErrorKind, Read, Write},
  net::Ipv4Addr,
  sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc,
  },
  thread::JoinHandle,
};

pub struct Tun {
  device: Option<tun::platform::Device>,
  in_tx: Option<Sender<Vec<u8>>>,
  out_rx: Option<Receiver<Vec<u8>>>,
  thread:
    Option<JoinHandle<Result<tun::platform::Device, (std::io::Error, tun::platform::Device)>>>,
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

const fn mask_from_prefix(prefix: u8) -> (u8, u8, u8, u8) {
  (
    (1u8 << (prefix % 8)).wrapping_sub(1),
    (1u8 << (prefix / 8 % 8)).wrapping_sub(1),
    (1u8 << (prefix / 16 % 8)).wrapping_sub(1),
    (1u8 << (prefix / 24 % 8)).wrapping_sub(1),
  )
}

#[cfg(test)]
mod tests {
  use crate::linux::mask_from_prefix;

  #[test]
  fn test_mask_from_prefix() {
    assert_eq!((255, 255, 255, 0), mask_from_prefix(24));
    assert_eq!((255, 255, 0, 0), mask_from_prefix(16));
    assert_eq!((255, 255, 255, 127), mask_from_prefix(25));
    assert_eq!((255, 0, 0, 0), mask_from_prefix(8));
    assert_eq!((127, 0, 0, 0), mask_from_prefix(1));
    assert_eq!((0, 0, 0, 0), mask_from_prefix(0));
  }
}

impl Tun {
  pub fn new(
    name: impl AsRef<str>,
    _pool: impl AsRef<str>,
    ip: Ipv4Addr,
    mask: u8,
  ) -> std::io::Result<Self> {
    let mut config = tun::Configuration::default();
    config
      .name(name)
      .address(ip)
      .netmask(mask_from_prefix(mask))
      .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
      config.packet_information(false);
    });
    let device = Some(tun::create(&config).map_err(|e| match e {
      tun::Error::Io(io) => io,
      e => std::io::Error::new(std::io::ErrorKind::Other, e),
    })?);

    Ok(Self {
      device,
      in_tx: None,
      out_rx: None,
      thread: None,
      terminate: Arc::new(AtomicBool::new(true)),
    })
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
}

impl Drop for Tun {
  fn drop(&mut self) {
    self.terminate.store(true, Ordering::Relaxed);
    if let Some(thread) = std::mem::replace(&mut self.thread, None) {
      drop(thread.join());
    }
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
    let mut device = self.device.take().ok_or(std::io::Error::new(
      std::io::ErrorKind::AlreadyExists,
      "Failed to register tun. Already registered",
    ))?;
    let terminate = Arc::clone(&self.terminate);
    self.thread = Some(std::thread::spawn(move || {
      let mut buf = vec![0u8; 4096];
      let mut inner = || loop {
        if terminate.load(Ordering::Relaxed) {
          return Ok(());
        }
        if let Ok(read) = device.read(&mut buf) {
          buf.truncate(read);
          let packet = buf.clone();
          buf.resize(4096, 0);
          out_tx
            .send(packet)
            .map_err(|err| std::io::Error::new(ErrorKind::ConnectionAborted, err))?;
          if interests.is_readable() {
            waker.wake()?;
          }
        }
        for packet in in_rx.try_iter() {
          if packet.len() > 0xFFFF {
            continue;
          }
          drop(device.write(&packet));
        }
        if interests.is_writable() {
          waker.wake()?;
        }
      };
      match inner() {
        Ok(()) => Ok(device),
        Err(err) => Err((err, device)),
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
    let Some(thread) = self.thread.take() else {
      return Err(std::io::Error::new(
        ErrorKind::Other,
        "Failed precondition: not registered yet",
      ));
    };
    let (res, device) = match thread.join().unwrap() {
      Ok(dev) => (Ok(()), dev),
      Err((err, dev)) => (Err(err), dev),
    };
    self.device = Some(device);
    res
  }
}
