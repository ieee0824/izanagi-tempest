//! Fixed Linux x86_64 UAPI layouts, checked against linux/kvm.h at build time.
#[repr(C)]
#[derive(Default)]
pub struct Registers {
    pub general: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub kind: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[repr(C)]
#[derive(Default)]
pub struct Dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Default)]
pub struct SpecialRegisters {
    pub segments: [Segment; 8],
    pub tables: [Dtable; 2],
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

#[repr(C)]
#[derive(Default)]
pub struct MemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

const _: () = {
    assert!(size_of::<Registers>() == 144);
    assert!(size_of::<Segment>() == 24);
    assert!(size_of::<Dtable>() == 16);
    assert!(size_of::<SpecialRegisters>() == 312);
    assert!(size_of::<MemoryRegion>() == 32);
    assert!(std::mem::offset_of!(Registers, rip) == 128);
    assert!(std::mem::offset_of!(SpecialRegisters, cr0) == 224);
};
