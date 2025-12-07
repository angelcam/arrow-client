// Copyright 2025 Angelcam, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::hash::{Hash, Hasher};

/// Custom option type with stable hash regardless of the system pointer width.
#[derive(Clone, Eq)]
pub enum StableHashOption<T> {
    None,
    Some(T),
}

impl<T> PartialEq for StableHashOption<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        if let Self::Some(a) = self {
            if let Self::Some(b) = other {
                a.eq(b)
            } else {
                false
            }
        } else {
            matches!(other, Self::None)
        }
    }
}

impl<T> Hash for StableHashOption<T>
where
    T: Hash,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        if let Self::Some(v) = self {
            // write the discriminant value
            state.write_u32(1);

            // ... and hash the inner data
            v.hash(state);
        } else {
            state.write_u32(0);
        }
    }
}

impl<T> From<Option<T>> for StableHashOption<T> {
    fn from(val: Option<T>) -> Self {
        match val {
            Some(v) => Self::Some(v),
            None => Self::None,
        }
    }
}

/// String wrapper with stable hash regardless of the system pointer width.
///
/// Even though the default implementation for string hashing currently does
/// not hash the string length, there is an alternative implementation being
/// considered that would hash it.
///
/// Let's be careful here and fix the hash implementation.
#[derive(Clone, Eq)]
pub struct StableHashString {
    inner: String,
}

impl PartialEq for StableHashString {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl Hash for StableHashString {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        state.write(self.inner.as_bytes());
        state.write_u8(0xff);
    }
}

impl From<String> for StableHashString {
    fn from(s: String) -> Self {
        Self { inner: s }
    }
}

/// Compute an u64 hash for a given hashable object using a stable hasher.
pub fn stable_hash<T: Hash>(val: &T) -> u64 {
    let mut hasher = StableHasher::new(512);

    val.hash(&mut hasher);

    hasher.finish()
}

/// Stable implementation of the Hasher trait.
struct StableHasher {
    data: Vec<u8>,
}

impl StableHasher {
    /// Create a new instance of StableHasher with a given capacity of the
    /// internal data buffer.
    fn new(capacity: usize) -> StableHasher {
        StableHasher {
            data: Vec::with_capacity(capacity),
        }
    }
}

impl Hasher for StableHasher {
    fn finish(&self) -> u64 {
        farmhash::fingerprint64(&self.data)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes)
    }
}
