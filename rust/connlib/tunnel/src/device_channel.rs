#![allow(clippy::module_inception)]

#[cfg(target_family = "unix")]
#[path = "device_channel/device_channel_unix.rs"]
mod device_channel;

#[cfg(target_family = "windows")]
#[path = "device_channel/device_channel_win.rs"]
mod device_channel;

use crate::device_channel::device_channel::tun::IfaceDevice;
use crate::ip_packet::MutableIpPacket;
use connlib_shared::error::ConnlibError;
use connlib_shared::messages::Interface;
use connlib_shared::{Callbacks, Error};
use ip_network::IpNetwork;
use std::borrow::Cow;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{ready, Context, Poll};

pub(crate) use device_channel::*;

pub struct Device {
    mtu: AtomicUsize,
    iface: IfaceDevice,
    io: DeviceIo,
}

impl Device {
    #[cfg(target_family = "unix")]
    pub(crate) async fn new(
        config: &Interface,
        callbacks: &impl Callbacks<Error = Error>,
    ) -> Result<Device, ConnlibError> {
        let (iface, stream) = IfaceDevice::new(config, callbacks).await?;
        iface.up().await?;
        let io = DeviceIo(stream);
        let mtu = AtomicUsize::new(ioctl::interface_mtu_by_name(iface.name())?);

        Ok(Device { io, mtu, iface })
    }

    #[cfg(target_family = "windows")]
    pub(crate) async fn new(
        config: &Interface,
        callbacks: &impl Callbacks<Error = Error>,
    ) -> Result<Device, ConnlibError> {
        todo!()
    }

    pub(crate) fn poll_read<'b>(
        &self,
        buf: &'b mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<MutableIpPacket<'b>>>> {
        let res = ready!(self.io.poll_read(&mut buf[..self.mtu()], cx))?;

        if res == 0 {
            return Poll::Ready(Ok(None));
        }

        Poll::Ready(Ok(Some(MutableIpPacket::new(&mut buf[..res]).ok_or_else(
            || {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "received bytes are not an IP packet",
                )
            },
        )?)))
    }

    pub(crate) fn mtu(&self) -> usize {
        self.mtu.load(Ordering::Relaxed)
    }

    #[cfg(target_family = "unix")]
    pub(crate) async fn add_route(
        &self,
        route: IpNetwork,
        callbacks: &impl Callbacks<Error = Error>,
    ) -> Result<Option<Device>, Error> {
        let Some((iface, stream)) = self.iface.add_route(route, callbacks).await? else {
            return Ok(None);
        };
        let io = DeviceIo(stream);
        let mtu = AtomicUsize::new(ioctl::interface_mtu_by_name(iface.name())?);

        Ok(Some(Device { io, mtu, iface }))
    }

    #[cfg(target_family = "windows")]
    pub(crate) async fn add_route(
        &self,
        route: IpNetwork,
        callbacks: &impl Callbacks<Error = Error>,
    ) -> Result<Option<Device>, Error> {
        todo!()
    }

    #[cfg(target_family = "unix")]
    pub(crate) fn refresh_mtu(&self) -> Result<usize, Error> {
        let mtu = ioctl::interface_mtu_by_name(self.iface.name())?;
        self.mtu.store(mtu, Ordering::Relaxed);

        Ok(mtu)
    }

    #[cfg(target_family = "windows")]
    pub(crate) fn refresh_mtu(&self) -> Result<usize, Error> {
        todo!()
    }

    pub fn write(&self, packet: Packet<'_>) -> io::Result<usize> {
        self.io.write(packet)
    }
}

pub enum Packet<'a> {
    Ipv4(Cow<'a, [u8]>),
    Ipv6(Cow<'a, [u8]>),
}

#[cfg(target_family = "unix")]
mod ioctl {
    use super::*;
    use std::os::fd::RawFd;
    use tun::SIOCGIFMTU;

    pub(crate) fn interface_mtu_by_name(name: &str) -> Result<usize, ConnlibError> {
        let socket = Socket::ip4()?;
        let request = Request::<GetInterfaceMtuPayload>::new(name)?;

        // Safety: The file descriptor is open.
        unsafe {
            exec(socket.fd, SIOCGIFMTU, &request)?;
        }

        Ok(request.payload.mtu as usize)
    }

    /// Executes the `ioctl` syscall on the given file descriptor with the provided request.
    ///
    /// # Safety
    ///
    /// The file descriptor must be open.
    pub(crate) unsafe fn exec<P>(
        fd: RawFd,
        code: libc::c_ulong,
        req: &Request<P>,
    ) -> Result<(), ConnlibError> {
        let ret = unsafe { libc::ioctl(fd, code as _, req) };

        if ret < 0 {
            return Err(io::Error::last_os_error().into());
        }

        Ok(())
    }

    /// Represents a control request to an IO device, addresses by the device's name.
    ///
    /// The payload MUST also be `#[repr(C)]` and its layout depends on the particular request you are sending.
    #[repr(C)]
    pub(crate) struct Request<P> {
        pub(crate) name: [std::ffi::c_uchar; libc::IF_NAMESIZE],
        pub(crate) payload: P,
    }

    /// A socket newtype which closes the file descriptor on drop.
    struct Socket {
        fd: RawFd,
    }

    impl Socket {
        fn ip4() -> io::Result<Socket> {
            // Safety: All provided parameters are constants.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_IP) };

            if fd == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { fd })
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            // Safety: This is the only call to `close` and it happens when `Guard` is being dropped.
            unsafe { libc::close(self.fd) };
        }
    }

    impl Request<GetInterfaceMtuPayload> {
        fn new(name: &str) -> io::Result<Self> {
            if name.len() > libc::IF_NAMESIZE {
                return Err(io::ErrorKind::InvalidInput.into());
            }

            let mut request = Request {
                name: [0u8; libc::IF_NAMESIZE],
                payload: Default::default(),
            };

            request.name[..name.len()].copy_from_slice(name.as_bytes());

            Ok(request)
        }
    }

    #[derive(Default)]
    #[repr(C)]
    struct GetInterfaceMtuPayload {
        mtu: libc::c_int,
    }
}
