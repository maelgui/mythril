use crate::boot_info::{self, BootInfo};
use crate::global_alloc;
use crate::memory::HostPhysAddr;
use alloc::vec::Vec;
use multiboot::information::{
    MemoryManagement, MemoryType, Multiboot, PAddr, SymbolType,
};

extern "C" {
    pub static MULTIBOOT_HEADER_START: u32;
    pub static MULTIBOOT_HEADER_END: u32;

    // The _value_ of the last byte of the mythril binary. The
    // address of this symbol is the actual end.
    pub static END_OF_BINARY: u8;
}

struct Mem;

impl MemoryManagement for Mem {
    unsafe fn paddr_to_slice(
        &self,
        addr: PAddr,
        size: usize,
    ) -> Option<&'static [u8]> {
        let ptr = core::mem::transmute(addr);
        Some(core::slice::from_raw_parts(ptr, size))
    }

    unsafe fn allocate(
        &mut self,
        _length: usize,
    ) -> Option<(PAddr, &mut [u8])> {
        None
    }

    unsafe fn deallocate(&mut self, addr: PAddr) {
        if addr != 0 {
            unimplemented!()
        }
    }
}

// NOTE: see multiboot2::header_location for more information
pub fn header_location() -> (u32, u32) {
    unsafe { (MULTIBOOT_HEADER_START, MULTIBOOT_HEADER_END) }
}

fn setup_global_alloc_region<'a, 'b>(
    info: &'a Multiboot<'a, 'b>,
) -> (u64, u64) {
    let regions = info
        .memory_regions()
        .expect("Missing multiboot memory regions");

    let available = regions.filter_map(|region| match region.memory_type() {
        MemoryType::Available => Some((
            region.base_address(),
            region.base_address() + region.length(),
        )),
        _ => None,
    });

    debug!("Modules:");
    let modules =
        info.modules()
            .expect("No multiboot modules found")
            .map(|module| {
                debug!("  0x{:x}-0x{:x}", module.start, module.end);
                (module.start, module.end)
            });

    // Avoid allocating over the actual mythril binary (just use 0 as the start
    // for now).
    let mythril_bounds =
        [(0 as u64, unsafe { &END_OF_BINARY as *const u8 as u64 })];
    debug!(
        "Mythril binary bounds: 0x{:x}-0x{:x}",
        mythril_bounds[0].0, mythril_bounds[0].1
    );

    let excluded = modules.chain(mythril_bounds.iter().copied());

    // TODO(alschwalm): For now, we just use the portion of the largest available
    // region that is above the highest excluded region.
    let max_excluded = excluded
        .max_by(|left, right| left.1.cmp(&right.1))
        .expect("No max excluded region");

    let largest_region = available
        .max_by(|left, right| (left.1 - left.0).cmp(&(right.1 - right.0)))
        .expect("No largest region");

    if largest_region.0 > max_excluded.1 {
        largest_region
    } else if max_excluded.1 > largest_region.0
        && max_excluded.1 < largest_region.1
    {
        (max_excluded.1, largest_region.1)
    } else {
        panic!("Unable to find suitable global alloc region")
    }
}

pub fn early_init_multiboot(addr: HostPhysAddr) -> BootInfo {
    let mut mem = Mem;

    let multiboot_info = unsafe {
        Multiboot::from_ptr(addr.as_u64(), &mut mem)
            .expect("Failed to create Multiboot structure")
    };

    let alloc_region = setup_global_alloc_region(&multiboot_info);

    info!(
        "Allocating from 0x{:x}-{:x}",
        alloc_region.0, alloc_region.1
    );

    unsafe {
        global_alloc::Allocator::allocate_from(alloc_region.0, alloc_region.1);
    }

    let modules = multiboot_info
        .modules()
        .expect("No multiboot modules found")
        .map(|module| boot_info::BootModule {
            address: HostPhysAddr::new(module.start),
            size: (module.end - module.start) as usize,
            identifier: module.string.map(alloc::string::String::from),
        })
        .collect::<Vec<_>>();

    BootInfo {
        modules: modules,
        rsdp: None,
    }
}
