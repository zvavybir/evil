/*
 * evilaes – Unsecure random number source
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
//! evilrng provides a unsecure source of cryptographical secure rando
//! mnumber and is written by an amateur for the sole purpose that he
//! learns a bit about cryptography.  It is very probably *very*
//! vulnerable, so **do not use evilrng** for real world
//! cryptographical purposes, but if you're just looking for a way to
//! get non obvious pattern based numbers and want to make sure that
//! your programme won't work on windows or will be not-GPL, you
//! actually may use this one evil\* crate.

use std::fs::File;
use std::io::{self, Read};

/// Provides cryptographical unsecure random numbers
#[derive(Debug)]
pub struct RngSource
{
    entropy: [u8; 256],
    used: usize,
}

impl Drop for RngSource
{
    fn drop(&mut self) {}
}

impl RngSource
{
    /// Creates a new unsecure random number source
    ///
    /// Creates a new unsecure random number source.  **Do not use for
    /// cryptography.**
    ///
    /// # Errors
    /// It returns an error if it couldn't be read from `/dev/urandom`
    pub fn new() -> Result<Self, io::Error>
    {
        let mut rv = Self {
            entropy: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            used: 256,
        };

        rv.fill()?;

        Ok(rv)
    }

    /// Gets unsecure random numbers
    ///
    /// Uses the available or newly loaded entropy to get a [`u8`].
    /// This is **not** the **cryptographical** secure type of random!
    ///
    /// # Errors
    /// It returns an error if not enough entropy was stored and
    /// getting additional entropy failed.
    pub fn get_u8(&mut self) -> Result<u8, io::Error>
    {
        if self.used + 1 > 256
        {
            self.fill()?;
        }

        let rv = self.entropy[self.used];

        self.used += 1;

        Ok(rv)
    }

    /// Gets unsecure random numbers
    ///
    /// Uses the available or newly loaded entropy to get a [`u32`].
    /// This is **not** the **cryptographical** secure type of random!
    ///
    /// # Errors
    /// It returns an error if not enough entropy was stored and
    /// getting additional entropy failed.
    pub fn get_u32(&mut self) -> Result<u32, io::Error>
    {
        if self.used + 4 > 256
        {
            self.fill()?;
        }

        let rv = (u32::from(self.entropy[self.used]) << 24)
            + (u32::from(self.entropy[self.used + 1]) << 16)
            + (u32::from(self.entropy[self.used + 2]) << 8)
            + u32::from(self.entropy[self.used + 3]);

        self.used += 4;

        Ok(rv)
    }

    fn fill(&mut self) -> Result<(), io::Error>
    {
        let mut fp = File::open("/dev/urandom")?;

        fp.read_exact(&mut self.entropy[0..self.used])?;

        self.used = 0;

        Ok(())
    }
}
