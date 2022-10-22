use proc_macro::TokenStream;
use quote::quote;

use syn::{parse_macro_input, parse_quote, Arm, Data, DeriveInput, Expr};

#[proc_macro_derive(ErrorCode, attributes(propagate_code))]
pub fn error_code_string(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    if let Data::Enum(r#enum) = &input.data {
        let ident = &input.ident;

        let mut to_string_arms = Vec::<Arm>::with_capacity(r#enum.variants.len());

        for variant in r#enum.variants.iter() {
            let variant_name = &variant.ident;
            let qualified_name = format!("{}::{}", ident, variant_name);

            let to_string_value = match &variant.fields {
                syn::Fields::Named(_) => {
                    quote!( #qualified_name )
                }
                syn::Fields::Unnamed(fields) => {
                    let selected_field = fields.unnamed.iter().position(|field| {
                        field
                            .attrs
                            .iter()
                            .any(|attr| attr.path.is_ident(&"propagate_code"))
                    });

                    if let Some(selected) = selected_field {
                        let tuple_pattern = (0..fields.unnamed.len())
                            .map(|index| if index == selected { "sub" } else { "_" })
                            .collect::<Vec<&str>>()
                            .join(", ");
                        let struct_tuple_pattern = format!("{}({})", qualified_name, tuple_pattern);
                        let struct_tuple_expt = syn::parse_str::<Expr>(&struct_tuple_pattern).unwrap();

                        quote!(
                            if let #struct_tuple_expt = self {
                                sub.to_error_code()
                            } else {
                                #qualified_name
                            }
                        )
                    } else {
                        quote!( #qualified_name )
                    }
                }
                syn::Fields::Unit => quote!( #qualified_name ),
            };

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
                #to_string_pattern => #to_string_value
            });
        }

        (quote! {
            impl ::error_codes::ErrorCode for #ident {
                fn to_error_code(&self) -> &'static str {
                    match self {
                        #(#to_string_arms),*
                    }
                }
            }
        })
        .into()
    } else {
        quote!(compile_error!(
            "Can only implement 'ErrorCode' on a enum"
        );)
        .into()
    }
}
