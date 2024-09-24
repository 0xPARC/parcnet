pub fn copy<T>(dst: &mut [T], src: &[T]) -> usize
where
    T: Copy,
{
    let len = core::cmp::min(src.len(), dst.len());
    dst[..len].copy_from_slice(&src[..len]);
    len
}

// The block size of the hash algorithm in bytes.
pub const BLOCK_SIZE: usize = 128;

#[derive(Clone)]
pub struct Blake512 {
    pub(crate) hash_size: usize,    // hash output size in bits (384 or 512)
    pub(crate) h: [u64; 8],         // current chain value
    pub(crate) s: [u64; 4],         // salt (zero by default)
    pub(crate) t: u64,              // message bits counter
    pub(crate) nullt: bool,         // special case for finalization: skip counter
    pub(crate) x: [u8; BLOCK_SIZE], // buffer for data not yet compressed
    pub(crate) nx: usize,           // number of bytes in buffer
}

static IV512: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

static IV384: [u64; 8] = [
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
];

impl Default for Blake512 {
    fn default() -> Self {
        Self {
            hash_size: 512,
            h: IV512,
            s: [0; 4],
            t: 0,
            nullt: false,
            x: [0; BLOCK_SIZE],
            nx: 0,
        }
    }
}

impl Blake512 {
    pub fn reset(&mut self) {
        if self.hash_size == 384 {
            self.h = IV384;
        } else {
            self.h = IV512;
        }
        self.t = 0;
        self.nx = 0;
        self.nullt = false;
    }

    fn size(&self) -> usize {
        self.hash_size >> 3
    }

    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    pub fn write(&mut self, p: &[u8]) -> u8 {
        let nn = p.len();
        let mut p = p;

        if self.nx > 0 {
            let n = std::cmp::min(p.len(), BLOCK_SIZE - self.nx);
            self.nx += copy(&mut self.x[self.nx..], p);

            if self.nx == BLOCK_SIZE {
                self.block(&self.x.clone());
                self.nx = 0;
            }

            p = &p[n..];
        }

        if p.len() >= BLOCK_SIZE {
            let n = p.len() & !(BLOCK_SIZE - 1);
            self.block(&p[..n]);
            p = &p[n..];
        }

        if !p.is_empty() {
            self.nx = copy(&mut self.x, p);
        }

        nn as u8
    }

    pub fn digest(&mut self, in_: &[u8]) -> Vec<u8> {
        let mut d = self.clone();
        // Make a copy of self so that caller can keep writing and summing.
        let nx = d.nx as u64;
        let l = d.t + (nx << 3);
        let mut len = [0u8; 16];

        // len[0 .. 7] = 0, because our counter has only 64 bits.
        len[8] = (l >> 56) as u8;
        len[9] = (l >> 48) as u8;
        len[10] = (l >> 40) as u8;
        len[11] = (l >> 32) as u8;
        len[12] = (l >> 24) as u8;
        len[13] = (l >> 16) as u8;
        len[14] = (l >> 8) as u8;
        len[15] = l as u8;

        if nx == 111 {
            // One padding byte.
            d.t -= 8;
            d.write(&[0x81]);
        } else {
            let mut pad = [0u8; 129];
            pad[0] = 0x80;
            if nx < 111 {
                // Enough space to fill the block.
                if nx == 0 {
                    d.nullt = true;
                }

                d.t = d.t.wrapping_sub(888 - (nx << 3));
                d.write(&pad[0..111 - nx as usize]);
            } else {
                // Need 2 compressions.
                d.t -= 1024 - (nx << 3);
                d.write(&pad[0..128 - nx as usize]);
                d.t -= 888;
                d.write(&pad[1..112]);
                d.nullt = true;
            }

            d.write(&[0x01]);

            d.t -= 8;
        }

        d.t -= 128;
        d.write(&len);

        let mut tmp: Vec<u8> = vec![0; d.size()];
        let mut j = 0;

        for s in d.h[..(d.hash_size >> 6)].iter() {
            tmp[j] = (s >> 56) as u8;
            tmp[j + 1] = (s >> 48) as u8;
            tmp[j + 2] = (s >> 40) as u8;
            tmp[j + 3] = (s >> 32) as u8;
            tmp[j + 4] = (s >> 24) as u8;
            tmp[j + 5] = (s >> 16) as u8;
            tmp[j + 6] = (s >> 8) as u8;
            tmp[j + 7] = *s as u8;
            j += 8;
        }

        let mut out: Vec<u8> = in_.to_vec();
        out.extend_from_slice(&tmp);
        out
    }

    pub fn set_salt(&mut self, s: &[u8]) {
        if s.len() != 32 {
            panic!("salt length must be 32 bytes");
        }

        let mut j = 0;
        for i in 0..4 {
            self.s[i] = (u64::from(s[j]) << 56)
                | (u64::from(s[j + 1]) << 48)
                | (u64::from(s[j + 2]) << 40)
                | (u64::from(s[j + 3]) << 32)
                | (u64::from(s[j + 4]) << 24)
                | (u64::from(s[j + 5]) << 16)
                | (u64::from(s[j + 6]) << 8)
                | u64::from(s[j + 7]);
            j += 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake512() {
        // Create a Blake512 object
        let mut hasher = Blake512::default();

        // Write input message
        hasher.write("hello world".as_bytes());

        // Finalize and get the hash
        let result = hasher.digest(&[]);

        // Convert the result to a hex string
        let hex_result = hex::encode(result);

        assert_eq!(hex_result, "1891a7b5ee05c04555d892303801784de65937a18d15dc08bc37f7c832c6892f46f5d7f1705a463534e1c18088f1b779dbd775002c7b8e14cf0de613e54c56e6");
    }
}
