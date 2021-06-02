/*
 * evilrng – Unsecure random number source
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

#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    rustdoc::missing_crate_level_docs,
    rust_2018_idioms,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![allow(clippy::suspicious_else_formatting, clippy::match_like_matches_macro)]

//! Unsecure random number source in pure rust
//!
//! evilrng provides a unsecure source of cryptographical secure
//! random number and is written by an amateur for the sole purpose
//! that he learns a bit about cryptography.  It is very probably
//! *very* vulnerable, so **do not use evilrng** for real world
//! cryptographical purposes, but if you're just looking for a way to
//! get non obvious pattern based numbers and want to make sure that
//! your programme won't be non-GPL, you actually may use this one
//! evil\* crate.
//!
//! **Note**: Since a recent update evilrng does not anymore rely on
//! `/dev/urandom` to get entropy, but uses an own **algorithm I have
//! designed myself**.  This is own crypto and so it's quite probable
//! that evilrng is **even on the algorithm level broken**.  The
//! advantage is that now all cryptographical code in or used by the
//! evil\* crates is fully written by me, what is exactly the goal.

use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{SystemTime, SystemTimeError};

use evilsha::{sha_2, ShaHash, ShaVersion};

static RNG_LOCKED: AtomicBool = AtomicBool::new(false);
static mut RNG_SOURCE: Option<InnerRngSource> = None;

/// Provides unsecure cryptographical secure random numbers
#[derive(Copy, Clone, Debug)]
pub struct RngSource;

#[derive(Debug)]
struct InnerRngSource
{
    entropy: [u8; 64],
    newentropy: Vec<u8>,
    used: usize,
    fresh: u8,
}

impl Default for RngSource
{
    fn default() -> Self
    {
        Self
    }
}

impl Drop for InnerRngSource
{
    #[allow(unsafe_code)]
    fn drop(&mut self)
    {
        // As far as I know always true, but this is my first time
        // working with atomics, so I'm a bit cautios.
        debug_assert!(RNG_LOCKED.load(Ordering::SeqCst));

        let replacer = Self {
            entropy: [0; 64],
            newentropy: vec![],
            used: 0,
            fresh: 0,
        };

        // SAFETY: There can always only be one `InnerRngSource`, so
        // we must have the lock.
        unsafe {
            RNG_SOURCE = Some(mem::replace(self, replacer));
        }

        RNG_LOCKED.store(false, Ordering::SeqCst);
    }
}

impl InnerRngSource
{
    #[allow(unsafe_code)]
    fn get() -> Self
    {
        while RNG_LOCKED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            thread::yield_now();
        }

        // As far as I know always true, but this is my first time
        // working with atomics, so I'm a bit cautios.
        debug_assert!(RNG_LOCKED.load(Ordering::SeqCst));

        // SAFETY: The lock was successfully acquired, so this is the
        // only point that accesses `RNG_SOURCE`.
        if let Some(x) = unsafe { mem::take(&mut RNG_SOURCE) }
        {
            x
        }
        else
        {
            let mut rv = Self {
                entropy: [0; 64],
                newentropy: vec![],
                used: 256,
                fresh: 255,
            };

            rv.add_new_entropy();
            rv.fill();

            rv
        }
    }

    fn get_u8(&mut self) -> u8
    {
        self.add_new_entropy();
        if self.used + 1 > 64
        {
            self.fill();
        }
        else
        {
            self.handle_fresh();
        }

        let rv = self.entropy[self.used];

        self.used += 1;

        rv
    }

    fn get_u32(&mut self) -> u32
    {
        self.add_new_entropy();
        if self.used + 4 > 64
        {
            self.fill();
        }
        else
        {
            self.handle_fresh();
        }

        let rv = (u32::from(self.entropy[self.used]) << 24)
            + (u32::from(self.entropy[self.used + 1]) << 16)
            + (u32::from(self.entropy[self.used + 2]) << 8)
            + u32::from(self.entropy[self.used + 3]);

        self.used += 4;

        rv
    }

    fn add_entropy(&mut self, mut entropy: Vec<u8>)
    {
        self.add_new_entropy();
        self.newentropy.append(&mut entropy);
        self.fill();
    }

    fn handle_fresh(&mut self)
    {
        if self.fresh != 0
        {
            self.fill();
            self.fresh -= 1;
        }
    }

    fn add_new_entropy(&mut self)
    {
        // Needed since there is no way known to me to avoid it.
        #[allow(clippy::cast_possible_truncation)]
        fn handle_error(
            val: &mut InnerRngSource,
        ) -> Result<(), SystemTimeError>
        {
            let start = SystemTime::now();
            val.newentropy.push(
                (SystemTime::now().duration_since(start)?.as_nanos() % 256)
                    as u8,
            );
            val.newentropy.push(
                (SystemTime::UNIX_EPOCH.duration_since(start)?.as_nanos()
                    % 256) as u8,
            );

            Ok(())
        }

        if handle_error(self).is_err()
        {
            self.newentropy.push(31);
            self.newentropy.push(41);
            self.newentropy.push(59);
        }
    }

    fn fill(&mut self)
    {
        match sha_2(&self.newentropy, ShaVersion::Sha512)
        {
            ShaHash::Sha512(x) =>
            {
                self.entropy = x;
                self.used = 0;
                self.newentropy.clear();
                for v in x
                {
                    self.newentropy.push(v);
                }
            }
            _ => unreachable!(),
        }
    }
}

impl RngSource
{
    /// Gets unsecure random numbers
    ///
    /// Uses the available or newly loaded entropy to get a [`u8`].
    /// This is **not** the **cryptographical** secure type of random!
    #[must_use]
    pub fn get_u8(self) -> u8
    {
        let _ = self;
        InnerRngSource::get().get_u8()
    }

    /// Gets unsecure random numbers
    ///
    /// Uses the available or newly loaded entropy to get a [`u32`].
    /// This is **not** the **cryptographical** secure type of random!
    #[must_use]
    pub fn get_u32(self) -> u32
    {
        let _ = self;
        InnerRngSource::get().get_u32()
    }

    /// Adds own entropy
    ///
    /// [`InnerRngSource`] usually uses time measurements for entropy, but
    /// that approach has limits, so if you have own entropy you can
    /// add it here and by that improve the quality of random numbers
    /// returned by `InnerRngSource`s.  Bad entropy (even constant zero or
    /// attacker-provided one) should not reduce the quality, but even
    /// without that you should **consider `InnerRngSource` broken!**
    pub fn add_entropy(self, entropy: Vec<u8>)
    {
        let _ = self;
        InnerRngSource::get().add_entropy(entropy)
    }
}

#[cfg(test)]
mod tests
{
    use super::RngSource;

    #[test]
    fn rng_test()
    {
        // We can't check on specific values, only that it doesn't panic
        for _ in 0..1000
        {
            let rng = RngSource;

            let _ = rng.get_u8();
            let _ = rng.get_u32();
            rng.add_entropy((0..100).map(|_| rng.get_u8()).collect());
            let _ = rng.get_u8();
            let _ = rng.get_u32();
        }
    }
}
