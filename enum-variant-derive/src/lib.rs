use proc_macro::TokenStream;
use quote::quote;

use syn::{parse_macro_input, DeriveInput, Data, Arm, parse_quote};

#[proc_macro_derive(EnumVariantNameString)]
pub fn enum_variant_name_string(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    if let Data::Enum(r#enum) = &input.data {
        let ident = &input.ident;

        let mut to_string_arms = Vec::<Arm>::with_capacity(r#enum.variants.len());

        for variant in r#enum.variants.iter() {

            let variant_name = &variant.ident;
            let variant_quoted = &variant.ident.to_string();
            let to_string_pattern = match &variant.fields {
                syn::Fields::Named(_) => {
                    quote!( Self::#variant_name {..} )
                }
                syn::Fields::Unnamed(_) => {
                    quote!( Self::#variant_name (..) )
                }
                syn::Fields::Unit => quote!( Self::#variant_name ),
            };

            to_string_arms.push(parse_quote! {
                #to_string_pattern => #variant_quoted
            });

        }

        (quote! {
            impl ::enum_variant::EnumVariantNameString for #ident {
                fn to_variant_name(&self) -> &'static str {
                    match self {
                        #(#to_string_arms),*
                    }
                }
            }
        })
        .into()

    } else {
        quote!(compile_error!(
            "Can only implement 'EnumVariantNameString' on a enum"
        );)
        .into()
    }
}