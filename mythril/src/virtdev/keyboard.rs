use core::convert::TryInto;

use crate::error::Result;
use crate::interrupt;
use crate::physdev::keyboard::*;
use crate::virtdev::{DeviceEvent, DeviceEventResponse, DeviceRegion, EmulatedDevice, Event, Port};
use alloc::vec::Vec;

#[derive(Debug)]
pub struct Keyboard8042{
    data_register: u8,
    status_register: Ps2StatusFlags,
    configuration: Ps2ConfigurationFlags,
    writing_configuration: bool,
    reseting: bool,
}

impl Keyboard8042 {
    const PS2_DATA: Port = 0x0060;
    const PS2_STATUS: Port = 0x0064;

    pub fn default() -> Self {
        Self {
            data_register: 0,
            status_register: Ps2StatusFlags::empty(),
            configuration: Ps2ConfigurationFlags::empty(),
            writing_configuration: false,
            reseting: false,
        }
    }

    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn write(&mut self, data: u8) {
        self.data_register = data;
        self.status_register.insert(Ps2StatusFlags::OUTPUT_BUFFER_FULL);
    }

    fn read(&mut self) -> Option<u8> {
        if self.status_register.contains(Ps2StatusFlags::OUTPUT_BUFFER_FULL) {
            self.status_register.remove(Ps2StatusFlags::OUTPUT_BUFFER_FULL);
            Some(self.data_register)
        }
        else {
            None
        }
    }
}

impl EmulatedDevice for Keyboard8042 {
    fn services(&self) -> Vec<DeviceRegion> {
        vec![
            DeviceRegion::PortIo(Self::PS2_DATA..=Self::PS2_DATA),
            DeviceRegion::PortIo(Self::PS2_STATUS..=Self::PS2_STATUS),
        ]
    }

    fn on_event(&mut self, event: Event) -> Result<()> {
        match event.kind {
            DeviceEvent::PortRead(port, mut val) => {
                if port == Self::PS2_DATA {
                    if let Some(key) = self.read() {
                        debug!("VM read port 1");
                        if self.reseting {
                            self.reseting = false;
                            self.write(0xAA);
                        }
                        val.copy_from_u32(key.into());
                    }
                    else {
                        val.copy_from_u32(0xff);
                    }    
                }
                else if port == Self::PS2_STATUS {
                    val.copy_from_u32(self.status_register.bits() as u32);
                }
            }
            DeviceEvent::HostKeyboardReceived(key) => {
                event
                    .responses
                    .push(DeviceEventResponse::GSI(interrupt::gsi::UART));
                self.write(key);
                debug!("Keyboard interrupt {}", key);
            }
            DeviceEvent::PortWrite(port, val) => {
                let val: u8 = val.try_into()?;
                debug!("PortWrite {} {:?}", port, val);
                if port == Self::PS2_STATUS {
                    match Command::from(val) {
                        Command::ReadConfig => {}
                        Command::WriteConfig => {
                            self.writing_configuration = true;
                        }
                        Command::DisableSecond => {
                        }
                        Command::EnableSecond => {}
                        Command::TestSecond => {}
                        Command::TestController => {
                            self.write(0x55);
                        }
                        Command::TestFirst => {
                            self.write(0x00);
                        }
                        Command::Diagnostic => {}
                        Command::DisableFirst => {
                        }
                        Command::EnableFirst => {}
                        Command::WriteSecond => {}
                    }
                }
                else {
                    if self.writing_configuration {
                        self.configuration = Ps2ConfigurationFlags::from_bits_truncate(val);
                        self.writing_configuration = false;
                    }
                    else {
                        match val {
                            0xFF => {
                                self.write(0xFA);
                                self.reseting = true;
                            },
                            0xF5 | 0xF2 | 0x02 => self.write(0xFA),
                            _ => ()
                        }
                    }
                }
            }

            _ => (),
        }
        Ok(())
    }
}
