pub trait EnumVariantNameString {
    fn to_variant_name(&self) -> &'static str;
}