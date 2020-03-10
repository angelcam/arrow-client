// Copyright 2019 Angelcam, Inc.
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

#![allow(clippy::missing_safety_doc)]

use std::alloc::Layout;

use libc::{c_void, size_t};

/// Allocate a block of memory with a given size.
#[no_mangle]
#[allow(clippy::cast_ptr_alignment)]
pub unsafe extern "C" fn ac__malloc(size: size_t) -> *mut c_void {
    let layout_size = std::mem::size_of::<Layout>();
    let layout = Layout::from_size_align_unchecked(layout_size + size, 1);
    let block = std::alloc::alloc(layout);

    *(block as *mut Layout) = layout;

    block.add(layout_size) as _
}

/// Free a given block of memory.
#[no_mangle]
#[allow(clippy::cast_ptr_alignment)]
pub unsafe extern "C" fn ac__free(ptr: *mut c_void) {
    let ptr = ptr as *mut u8;

    let layout_size = std::mem::size_of::<Layout>();
    let block = ptr.sub(layout_size);
    let layout = *(block as *mut Layout);

    std::alloc::dealloc(block, layout);
}
