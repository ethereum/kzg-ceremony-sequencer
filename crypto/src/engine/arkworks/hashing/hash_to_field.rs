// This code is backported from arkworks-rs,
// https://github.com/arkworks-rs/algebra/, which is licensed under the
// MIT license.

// The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use crate::engine::arkworks::hashing::xmd_expander::{Expander, ExpanderXmd};
use ark_ff::{Field, FpParameters, PrimeField};
use digest::DynDigest;

/// Trait for hashing messages to field elements.
pub trait HashToField<F: Field>: Sized {
    /// Initialises a new hash-to-field helper struct.
    ///
    /// # Arguments
    ///
    /// * `domain` - bytes that get concatenated with the `msg` during hashing,
    ///   in order to separate potentially interfering instantiations of the
    ///   hasher.
    fn new(domain: &[u8]) -> Self;

    /// Hash an arbitrary `msg` to #`count` elements from field `F`.
    fn hash_to_field(&self, msg: &[u8], count: usize) -> Vec<F>;
}

/// This field hasher constructs a Hash-To-Field based on a fixed-output hash
/// function, like SHA2, SHA3 or Blake2.
/// The implementation aims to follow the specification in [Hashing to Elliptic Curves (draft)](https://tools.ietf.org/pdf/draft-irtf-cfrg-hash-to-curve-13.pdf).
pub struct DefaultFieldHasher<H: Default + DynDigest + Clone, const SEC_PARAM: usize = 128> {
    expander:          ExpanderXmd<H>,
    len_per_base_elem: usize,
}

impl<F: Field, H: Default + DynDigest + Clone, const SEC_PARAM: usize> HashToField<F>
    for DefaultFieldHasher<H, SEC_PARAM>
{
    fn new(dst: &[u8]) -> Self {
        // The final output of `hash_to_field` will be an array of field
        // elements from F::BaseField, each of size `len_per_elem`.
        let len_per_base_elem = get_len_per_elem::<F, SEC_PARAM>();

        let expander = ExpanderXmd {
            hasher:     H::default(),
            dst:        dst.to_vec(),
            block_size: len_per_base_elem,
        };

        DefaultFieldHasher {
            expander,
            len_per_base_elem,
        }
    }

    fn hash_to_field(&self, message: &[u8], count: usize) -> Vec<F> {
        let m = F::extension_degree() as usize;

        // The user imposes a `count` of elements of F_p^m to output per input msg,
        // each field element comprising `m` BasePrimeField elements.
        let len_in_bytes = count * m * self.len_per_base_elem;
        let uniform_bytes = self.expander.expand(message, len_in_bytes);

        let mut output = Vec::with_capacity(count);
        let mut base_prime_field_elems = Vec::with_capacity(m);
        for i in 0..count {
            base_prime_field_elems.clear();
            for j in 0..m {
                let elm_offset = self.len_per_base_elem * (j + i * m);
                let val = F::BasePrimeField::from_be_bytes_mod_order(
                    &uniform_bytes[elm_offset..][..self.len_per_base_elem],
                );
                base_prime_field_elems.push(val);
            }
            let f = F::from_base_prime_field_elems(&base_prime_field_elems).unwrap();
            output.push(f);
        }

        output
    }
}

/// This function computes the length in bytes that a hash function should
/// output for hashing an element of type `Field`.
/// See section 5.1 and 5.3 of the
/// [IETF hash standardization draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/)
fn get_len_per_elem<F: Field, const SEC_PARAM: usize>() -> usize {
    // ceil(log(p))
    let base_field_size_in_bits =
        <<F::BasePrimeField as PrimeField>::Params as FpParameters>::MODULUS_BITS as usize;
    // ceil(log(p)) + security_parameter
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + SEC_PARAM;
    // ceil( (ceil(log(p)) + security_parameter) / 8)
    let bytes_per_base_field_elem =
        ((base_field_size_with_security_padding_in_bits + 7) / 8) as u64;
    bytes_per_base_field_elem as usize
}
