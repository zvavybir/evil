/*
 * evilaes – Unsecure SHA 2 implementation
 * Copyright (C) 2021 Matthias Kaak
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed without the hope that it will be useful,
 * and WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::num::Wrapping;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShaVersion
{
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShaHash
{
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}

struct PaddingWrapper256<'a>(&'a [u8]);

impl<'a> PaddingWrapper256<'a>
{
    fn get(&self, i: usize) -> u8
    {
        let mut amount_pad = 120 - ((self.0.len() + 1) % 64);
        if amount_pad >= 64
        {
            amount_pad -= 64;
        }
        amount_pad += self.0.len();

        if i < self.0.len()
        {
            self.0[i]
        }
        else if i == self.0.len()
        {
            1 << 7
        }
        else if i <= amount_pad
        {
            0
        }
        else
        {
            let i = 8 - (i - amount_pad);
            (((self.0.len() << 3) as u64) >> (i * 8)) as u8
        }
    }
}

fn sha_256_pad(mes: &[u8]) -> Vec<[u32; 16]>
{
    let mut rv = Vec::with_capacity(mes.len() / 64 + 1);
    let padding_wrapper = PaddingWrapper256(mes);
    let mut amount_pad = 120 - ((mes.len() + 1) % 64);
    if amount_pad >= 64
    {
        amount_pad -= 64;
    }

    for i in 0..(mes.len() + amount_pad + 9) / 64
    {
        let mut new: [u32; 16] = Default::default();

        for (j, new) in new.iter_mut().enumerate()
        {
            *new = ((padding_wrapper.get(i * 64 + j * 4) as u32) << 24)
                + ((padding_wrapper.get(i * 64 + j * 4 + 1) as u32) << 16)
                + ((padding_wrapper.get(i * 64 + j * 4 + 2) as u32) << 8)
                + (padding_wrapper.get(i * 64 + j * 4 + 3) as u32);
        }

        rv.push(new);
    }

    rv
}

struct PaddingWrapper512<'a>(&'a [u8]);

impl<'a> PaddingWrapper512<'a>
{
    fn get(&self, i: usize) -> u8
    {
        let mut amount_pad = 240 - ((self.0.len() + 1) % 128);
        if amount_pad >= 128
        {
            amount_pad -= 128;
        }
        amount_pad += self.0.len();

        if i < self.0.len()
        {
            self.0[i]
        }
        else if i == self.0.len()
        {
            1 << 7
        }
        else if i <= amount_pad
        {
            0
        }
        else
        {
            let i = 16 - (i - amount_pad);
            (((self.0.len() as u128) << 3) >> (i * 8)) as u8
        }
    }
}

fn sha_512_pad(mes: &[u8]) -> Vec<[u64; 16]>
{
    let mut rv = Vec::with_capacity(mes.len() / 128 + 1);
    let padding_wrapper = PaddingWrapper512(mes);
    let mut amount_pad = 240 - ((mes.len() + 1) % 128);
    if amount_pad >= 128
    {
        amount_pad -= 128;
    }

    for i in 0..(mes.len() + amount_pad + 17) / 128
    {
        let mut new: [u64; 16] = Default::default();

        for (j, new) in new.iter_mut().enumerate()
        {
            *new = ((padding_wrapper.get(i * 128 + j * 8) as u64) << 56)
                + ((padding_wrapper.get(i * 128 + j * 8 + 1) as u64) << 48)
                + ((padding_wrapper.get(i * 128 + j * 8 + 2) as u64) << 40)
                + ((padding_wrapper.get(i * 128 + j * 8 + 3) as u64) << 32)
                + ((padding_wrapper.get(i * 128 + j * 8 + 4) as u64) << 24)
                + ((padding_wrapper.get(i * 128 + j * 8 + 5) as u64) << 16)
                + ((padding_wrapper.get(i * 128 + j * 8 + 6) as u64) << 8)
                + (padding_wrapper.get(i * 128 + j * 8 + 7) as u64);
        }

        rv.push(new);
    }

    rv
}

pub fn sha_256(mes: &[[u32; 16]]) -> [u8; 32]
{
    let mut hs: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
        0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    for chunk in mes
    {
        let mut w: [u32; 64] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        for (i, &v) in chunk.iter().enumerate()
        {
            w[i] = v;
        }

        for i in 16..64
        {
            let t0 = w[i - 15] >> 3;
            let t1 = w[i - 2] >> 10;
            let s0 =
                w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ t0;
            let s1 =
                w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ t1;
            w[i] = (Wrapping(w[i - 16])
                + Wrapping(s0)
                + Wrapping(w[i - 7])
                + Wrapping(s1))
            .0;
        }

        let mut a_to_h = hs;

        for i in 0..64
        {
            let s1 = a_to_h[4].rotate_right(6)
                ^ a_to_h[4].rotate_right(11)
                ^ a_to_h[4].rotate_right(25);
            let ch = (a_to_h[4] & a_to_h[5]) ^ (!a_to_h[4] & a_to_h[6]);
            let tmp1 = (Wrapping(a_to_h[7])
                + Wrapping(s1)
                + Wrapping(ch)
                + Wrapping(k[i])
                + Wrapping(w[i]))
            .0;
            let s0 = a_to_h[0].rotate_right(2)
                ^ a_to_h[0].rotate_right(13)
                ^ a_to_h[0].rotate_right(22);
            let maj = (a_to_h[0] & a_to_h[1])
                ^ (a_to_h[1] & a_to_h[2])
                ^ (a_to_h[2] & a_to_h[0]);
            let tmp2 = (Wrapping(s0) + Wrapping(maj)).0;

            a_to_h[7] = a_to_h[6];
            a_to_h[6] = a_to_h[5];
            a_to_h[5] = a_to_h[4];
            a_to_h[4] = (Wrapping(a_to_h[3]) + Wrapping(tmp1)).0;
            a_to_h[3] = a_to_h[2];
            a_to_h[2] = a_to_h[1];
            a_to_h[1] = a_to_h[0];
            a_to_h[0] = (Wrapping(tmp1) + Wrapping(tmp2)).0;
        }

        hs.iter_mut()
            .zip(a_to_h.iter())
            .for_each(|(h, a)| *h = (Wrapping(*h) + Wrapping(*a)).0);
    }

    let mut rv: [u8; 32] = Default::default();

    for i in 0..8
    {
        rv[i * 4] = (hs[i] >> 24) as u8;
        rv[i * 4 + 1] = ((hs[i] >> 16) % 256) as u8;
        rv[i * 4 + 2] = ((hs[i] >> 8) % 256) as u8;
        rv[i * 4 + 3] = (hs[i] % 256) as u8;
    }

    rv
}

pub fn sha_512(mes: &[[u64; 16]], version: ShaVersion) -> ShaHash
{
    assert_ne!(version, ShaVersion::Sha256, "Use `sha_256` for 256 bit");

    let mut hs: [u64; 8] = if version == ShaVersion::Sha512
    {
        [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ]
    }
    else
    {
        [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ]
    };
    let k: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    for chunk in mes
    {
        let mut w: [u64; 80] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        for (i, &v) in chunk.iter().enumerate()
        {
            w[i] = v;
        }

        for i in 16..80
        {
            let t0 = w[i - 15] >> 7;
            let t1 = w[i - 2] >> 6;
            let s0 =
                w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ t0;
            let s1 =
                w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ t1;
            w[i] = (Wrapping(w[i - 16])
                + Wrapping(s0)
                + Wrapping(w[i - 7])
                + Wrapping(s1))
            .0;
        }

        let mut a_to_h = hs;

        for i in 0..80
        {
            let s1 = a_to_h[4].rotate_right(14)
                ^ a_to_h[4].rotate_right(18)
                ^ a_to_h[4].rotate_right(41);
            let ch = (a_to_h[4] & a_to_h[5]) ^ (!a_to_h[4] & a_to_h[6]);
            let tmp1 = (Wrapping(a_to_h[7])
                + Wrapping(s1)
                + Wrapping(ch)
                + Wrapping(k[i])
                + Wrapping(w[i]))
            .0;
            let s0 = a_to_h[0].rotate_right(28)
                ^ a_to_h[0].rotate_right(34)
                ^ a_to_h[0].rotate_right(39);
            let maj = (a_to_h[0] & a_to_h[1])
                ^ (a_to_h[1] & a_to_h[2])
                ^ (a_to_h[2] & a_to_h[0]);
            let tmp2 = (Wrapping(s0) + Wrapping(maj)).0;

            a_to_h[7] = a_to_h[6];
            a_to_h[6] = a_to_h[5];
            a_to_h[5] = a_to_h[4];
            a_to_h[4] = (Wrapping(a_to_h[3]) + Wrapping(tmp1)).0;
            a_to_h[3] = a_to_h[2];
            a_to_h[2] = a_to_h[1];
            a_to_h[1] = a_to_h[0];
            a_to_h[0] = (Wrapping(tmp1) + Wrapping(tmp2)).0;
        }

        hs.iter_mut()
            .zip(a_to_h.iter())
            .for_each(|(h, a)| *h = (Wrapping(*h) + Wrapping(*a)).0);
    }

    match version
    {
        ShaVersion::Sha512 =>
        {
            let mut rv: [u8; 64] = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0,
            ];

            for i in 0..8
            {
                rv[i * 8] = (hs[i] >> 56) as u8;
                rv[i * 8 + 1] = ((hs[i] >> 48) % 256) as u8;
                rv[i * 8 + 2] = ((hs[i] >> 40) % 256) as u8;
                rv[i * 8 + 3] = ((hs[i] >> 32) % 256) as u8;
                rv[i * 8 + 4] = ((hs[i] >> 24) % 256) as u8;
                rv[i * 8 + 5] = ((hs[i] >> 16) % 256) as u8;
                rv[i * 8 + 6] = ((hs[i] >> 8) % 256) as u8;
                rv[i * 8 + 7] = (hs[i] % 256) as u8;
            }

            ShaHash::Sha512(rv)
        }
        ShaVersion::Sha384 =>
        {
            let mut rv: [u8; 48] = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ];

            for i in 0..6
            {
                rv[i * 8] = (hs[i] >> 56) as u8;
                rv[i * 8 + 1] = ((hs[i] >> 48) % 256) as u8;
                rv[i * 8 + 2] = ((hs[i] >> 40) % 256) as u8;
                rv[i * 8 + 3] = ((hs[i] >> 32) % 256) as u8;
                rv[i * 8 + 4] = ((hs[i] >> 24) % 256) as u8;
                rv[i * 8 + 5] = ((hs[i] >> 16) % 256) as u8;
                rv[i * 8 + 6] = ((hs[i] >> 8) % 256) as u8;
                rv[i * 8 + 7] = (hs[i] % 256) as u8;
            }

            ShaHash::Sha384(rv)
        }
        ShaVersion::Sha256 => unreachable!("explicitly checked"),
    }
}

pub fn sha_2(mes: &[u8], version: ShaVersion) -> ShaHash
{
    match version
    {
        ShaVersion::Sha256 => ShaHash::Sha256(sha_256(&sha_256_pad(mes))),
        _ => sha_512(&sha_512_pad(mes), version),
    }
}

#[cfg(test)]
mod tests
{
    use crate::{sha_2, sha_256_pad, sha_512_pad, ShaHash, ShaVersion};

    #[test]
    fn padding_tests()
    {
        let input = "abc".bytes().collect::<Vec<_>>();
        assert_eq!(input.len(), 3);
        let output256 =
            vec![[1633837952, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24]];
        let output512 = vec![[
            7017280570803617792,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            24,
        ]];
        assert_eq!(sha_256_pad(&input), output256);
        assert_eq!(sha_512_pad(&input), output512);
    }

    #[test]
    fn sha_256_test()
    {
        assert_eq!(
            sha_2(&"abc".bytes().collect::<Vec<_>>(), ShaVersion::Sha256),
            ShaHash::Sha256([
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41,
                0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3,
                0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
                0x15, 0xad
            ])
        );
    }

    #[test]
    fn sha_512_test()
    {
        /*
         * abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
         * hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu
         */
        assert_eq!(
            sha_2(
                &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                    .bytes()
                    .collect::<Vec<_>>(),
                ShaVersion::Sha512
            ),
            ShaHash::Sha512([
                0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4,
                0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6,
                0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88,
                0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
                0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3,
                0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b,
                0x87, 0x4b, 0xe9, 0x09
            ])
        );
    }

    #[test]
    fn sha_384_test()
    {
        assert_eq!(
            sha_2(&"".bytes().collect::<Vec<_>>(), ShaVersion::Sha384),
            ShaHash::Sha384([
                0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9,
                0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11,
                0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6,
                0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
                0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
            ])
        );
    }
}
