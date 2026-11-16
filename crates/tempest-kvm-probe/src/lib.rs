//! Fixed dummy KVM investigation. No image, command, path or launch permit API.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod abi;
pub const GUEST: [u8; 5] = [0xb0, 0x2a, 0xe6, 0xe9, 0xf4];
pub const RAM_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExitSequence {
    io_seen: bool,
    complete: bool,
    failed: bool,
}

impl ExitSequence {
    /// Linux x86_64 kvm_run fixed header/IO union, decoded without casts.
    pub fn accept(&mut self, mapping: &[u8]) -> bool {
        let passed = self.accept_inner(mapping);
        self.failed |= !passed;
        passed
    }
    fn accept_inner(&mut self, mapping: &[u8]) -> bool {
        if self.failed || self.complete || mapping.len() < 48 {
            return false;
        }
        let reason = u32::from_le_bytes(mapping[8..12].try_into().unwrap());
        if !self.io_seen {
            if reason != 2
                || mapping[32] != 1
                || mapping[33] != 1
                || u16::from_le_bytes(mapping[34..36].try_into().unwrap()) != 0xe9
                || u32::from_le_bytes(mapping[36..40].try_into().unwrap()) != 1
            {
                return false;
            }
            let offset = u64::from_le_bytes(mapping[40..48].try_into().unwrap());
            let Ok(offset) = usize::try_from(offset) else {
                return false;
            };
            if offset < 48 || mapping.get(offset) != Some(&0x2a) {
                return false;
            }
            self.io_seen = true;
            true
        } else if reason == 5 {
            self.complete = true;
            true
        } else {
            false
        }
    }
    pub fn complete(&self) -> bool {
        self.complete && !self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn io() -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
        bytes[32] = 1;
        bytes[33] = 1;
        bytes[34..36].copy_from_slice(&0xe9_u16.to_le_bytes());
        bytes[36..40].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&128_u64.to_le_bytes());
        bytes[128] = 0x2a;
        bytes
    }
    #[test]
    fn only_fixed_io_then_halt_completes() {
        let mut sequence = ExitSequence::default();
        let mut bytes = io();
        assert!(sequence.accept(&bytes));
        assert!(!sequence.complete());
        bytes[8..12].copy_from_slice(&5_u32.to_le_bytes());
        assert!(sequence.accept(&bytes));
        assert!(sequence.complete());
        assert!(!sequence.accept(&bytes));
        assert!(!sequence.complete());
    }
    #[test]
    fn truncated_wrong_io_and_out_of_bounds_offsets_fail_closed() {
        for length in [0, 8, 12, 32, 47] {
            assert!(!ExitSequence::default().accept(&io()[..length]));
        }
        for offset in [0, 47, 4096, u64::MAX] {
            let mut bytes = io();
            bytes[40..48].copy_from_slice(&offset.to_le_bytes());
            let mut sequence = ExitSequence::default();
            assert!(!sequence.accept(&bytes));
            assert!(!sequence.accept(&io()));
        }
        for index in [8, 32, 33, 34, 36, 128] {
            let mut bytes = io();
            bytes[index] ^= 1;
            assert!(!ExitSequence::default().accept(&bytes));
        }
    }
}
