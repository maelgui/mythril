use crate::error::{Error, Result};
use crate::memory::GuestPhysAddr;
use crate::virtdev::{
    DeviceEvent, DeviceRegion, EmulatedDevice, Event, Port, PortReadRequest,
    PortWriteRequest,
};
use alloc::vec::Vec;
use x86::io::{inb, outb, outw};
use core::convert::{TryFrom, TryInto};
use num_enum::TryFromPrimitive;

#[derive(Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum VgaRegister {
    HorizontalTotalChars = 0x00,
    HorizontalCharsPerLine = 0x01,
    HorizontalSyncPosition = 0x02,
    HorizontalSyncWidthInChars = 0x03,
    VirticalTotalLines = 0x04,
    VirticalTotalAdjust = 0x05,
    VirticalDisplayedRows = 0x06,
    VirticalSyncPosition = 0x07,
    InterlaceMode = 0x08,
    MaxScanLineAddr = 0x09,
    CursorStart = 0x0a,
    CursorEnd = 0x0b,
    StartAddrMsb = 0x0c,
    StartAddrLsb = 0x0d,
    CursorAddrMsb = 0x0e,
    CursorAddrLsb = 0x0f,
}

#[derive(Debug)]
pub struct VgaController {
    index: VgaRegister,

    registers: [u8; 0x10],
}

#[allow(dead_code)]
impl VgaController {
    const VGA_INDEX: Port = 0x03D4;
    const VGA_DATA: Port = 0x03D5;

    pub fn new() -> Result<Self> {
        Ok(Self {
            index: VgaRegister::HorizontalTotalChars,

            registers: [
                0x61, // HorizontalTotalChars
                0x50, // HorizontalCharsPerLine
                0x52, // HorizontalSyncPosition
                0x0f, // HorizontalSyncWidthInChars
                0x19, // VirticalTotalLines
                0x06, // VirticalTotalAdjust
                0x19, // VirticalDisplayedRows
                0x19, // VirticalSyncPosition
                0x02, // InterlaceMode
                0x0d, // MaxScanLineAddr
                0x0b, // CursorStart
                0x0c, // CursorEnd
                0x00, // StartAddrMsb
                0x00, // StartAddrLsb
                0x00, // CursorAddrMsb
                0x00, // CursorAddrLsb
            ],
        })
    }

    fn on_port_read(
        &mut self,
        port: Port,
        mut val: PortReadRequest,
    ) -> Result<()> {
                unsafe {
                    let v = inb(port);
                    val.copy_from_u32(v as u32);
            }
        Ok(())
    }

    fn on_port_write(
        &mut self,
        port: Port,
        val: PortWriteRequest,
    ) -> Result<()> {
        match val {
                PortWriteRequest::OneByte(b) => {
                    unsafe {
                        outb(port, b[0]);
                    }
                }

                // The VGA controller allows a register update and data write
                // in one operation (and linux actually does this), so handle
                // that here
                PortWriteRequest::TwoBytes(bytes) => {
                    unsafe {
                        outw(port, (bytes[1] as u16) + (bytes[0] as u16) << 8);
                    }
                }
                _ => {
                    panic!(
                        "Invalid port write to VGA index register: {:?}",
                        val
                    );
                }
        }
        Ok(())
    }
}

impl EmulatedDevice for VgaController {
    fn services(&self) -> Vec<DeviceRegion> {
        vec![
            // vga stuff
            //DeviceRegion::PortIo(Self::VGA_INDEX..=Self::VGA_DATA),
            DeviceRegion::PortIo(0x3B4..=0x3DA),
            DeviceRegion::MemIo(GuestPhysAddr::new(0xA0000)..=GuestPhysAddr::new(0xBFFFF)),
        ]
    }

    fn on_event(&mut self, event: Event) -> Result<()> {
        //panic!("HERE !");
        match event.kind {
            DeviceEvent::PortRead(port, val) => self.on_port_read(port, val)?,
            DeviceEvent::PortWrite(port, val) => {
                self.on_port_write(port, val)?
            }
            _ => {
                panic!("HERE !");
            },
        }
        Ok(())
    }
}
