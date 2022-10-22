use proc_macro::TokenStream;
use quote::quote;

use syn::{parse_macro_input, DeriveInput, Data, Arm, parse_quote, PredicateType, PatTupleStruct, Expr};

#[proc_macro_derive(EnumVariantNameString, attributes(variant))]
pub fn enum_variant_name_string(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    if let Data::Enum(r#enum) = &input.data {
        let ident = &input.ident;

        let mut to_string_arms = Vec::<Arm>::with_capacity(r#enum.variants.len());

        for variant in r#enum.variants.iter() {
            let variant_name = &variant.ident;

            let variant_quoted = format!("{}::{}", ident.to_string(), variant_name.to_string());

            let to_string_value = match &variant.fields {
                syn::Fields::Named(_) => {
                    quote!( #variant_quoted )
                }
                syn::Fields::Unnamed(fields) => {
                    let selected_field = fields.unnamed.iter().position(|field| {
                        field.attrs.iter().any(|attr| {
                            attr.path.is_ident(&"variant")
                        })
                    });

                    if let Some(selected) = selected_field {
                        let to_sub_match = (0..fields.unnamed.len()).map(|index| {
                            if index == selected {
                                "sub"
                            } else {
                                "_"
                            }
                        }).collect::<Vec<&str>>().join(", ");
                        let sub_match = 
                            format!("{}({})", variant_quoted, to_sub_match);
                        let sub_expr = syn::parse_str::<Expr>(&sub_match).unwrap();
                        println!("SUB MATCH {:?}", sub_match);

                        //let sub_match_parsed: PatTupleStruct = parse_quote!(sub_match);
                        let x = quote!(
                            if let #sub_expr = self {
                                sub.to_variant_name()
                            } else {
                                #variant_quoted
                            }
                        );

                        println!("STREAM {}", x);
                        x
                    } else {
                        quote!( #variant_quoted )
                    }   
                }
                syn::Fields::Unit => quote!( #variant_quoted ),
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