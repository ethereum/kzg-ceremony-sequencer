use ark_bls12_381::Fq;
use ark_ff::{Field, QuadExtField, QuadExtParameters};

pub trait ToBasePrimeFieldIterator
where
    Self: Field,
{
    fn base_field_iterator<'a>(
        &'a self,
    ) -> Box<dyn DoubleEndedIterator<Item = &Self::BasePrimeField> + 'a>;
}

impl ToBasePrimeFieldIterator for Fq {
    fn base_field_iterator<'a>(
        &'a self,
    ) -> Box<dyn DoubleEndedIterator<Item = &Self::BasePrimeField> + 'a> {
        Box::new(std::iter::once(self))
    }
}

impl<P: QuadExtParameters> ToBasePrimeFieldIterator for QuadExtField<P>
where
    P::BaseField: ToBasePrimeFieldIterator,
{
    fn base_field_iterator<'a>(
        &'a self,
    ) -> Box<dyn DoubleEndedIterator<Item = &Self::BasePrimeField> + 'a> {
        Box::new(
            self.c0
                .base_field_iterator()
                .chain(self.c1.base_field_iterator()),
        )
    }
}
