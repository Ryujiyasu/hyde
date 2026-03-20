extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Fields, Meta, Expr, Lit};

/// Attribute macro that makes a struct protectable by a TEE.
///
/// Generates:
/// - `fn protect(ctx, fields...) -> Result<Protected<Self>>` constructor
/// - `Zeroize` on Drop (if `zeroize = true`, the default)
/// - Derives `Serialize`, `Deserialize` on the struct
///
/// # Example
/// ```ignore
/// #[veil::protect]
/// struct DocumentKey {
///     key_material: [u8; 32],
/// }
///
/// // Generated API:
/// let protected = DocumentKey::protect(&mut ctx, key_material)?;
/// let doc_key: DocumentKey = protected.unprotect(&mut ctx)?;
/// ```
///
/// # Attributes
/// - `zeroize = false` — disable Zeroize on Drop (default: true)
#[proc_macro_attribute]
pub fn protect(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let attrs = parse_protect_attrs(attr);

    let name = &input.ident;
    let vis = &input.vis;
    let generics = &input.generics;

    // Extract named fields
    let fields = match &input.data {
        syn::Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "#[veil::protect] only supports structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input.ident,
                "#[veil::protect] can only be applied to structs",
            )
            .to_compile_error()
            .into();
        }
    };

    // Build the `protect()` method parameters and struct construction
    let field_params: Vec<_> = fields
        .iter()
        .map(|f| {
            let fname = &f.ident;
            let fty = &f.ty;
            quote! { #fname: #fty }
        })
        .collect();

    let field_names: Vec<_> = fields.iter().map(|f| &f.ident).collect();

    // Generate Zeroize on Drop if enabled
    let zeroize_impl = if attrs.zeroize {
        let zeroize_fields: Vec<_> = fields
            .iter()
            .map(|f| {
                let fname = &f.ident;
                quote! { zeroize::Zeroize::zeroize(&mut self.#fname); }
            })
            .collect();

        quote! {
            impl #generics Drop for #name #generics {
                fn drop(&mut self) {
                    #(#zeroize_fields)*
                }
            }
        }
    } else {
        quote! {}
    };

    // Keep existing attributes (except our #[veil::protect])
    let existing_attrs: Vec<_> = input
        .attrs
        .iter()
        .filter(|a| !a.path().is_ident("protect"))
        .collect();

    let expanded = quote! {
        #(#existing_attrs)*
        #[derive(serde::Serialize, serde::Deserialize)]
        #vis struct #name #generics {
            #fields
        }

        impl #generics #name #generics {
            /// Protect this value using a TEE backend.
            ///
            /// Serializes the struct, encrypts it via `VeilContext`, and returns
            /// a `Protected<Self>` that can only be decrypted with the same TEE.
            #vis fn protect(
                ctx: &mut veil_tee_core::VeilContext,
                #(#field_params),*
            ) -> veil_tee_core::Result<veil_tee_core::Protected<Self>> {
                let value = Self { #(#field_names),* };
                veil_tee_core::Protected::new(ctx, &value)
            }
        }

        #zeroize_impl
    };

    expanded.into()
}

struct ProtectAttrs {
    zeroize: bool,
}

fn parse_protect_attrs(attr: TokenStream) -> ProtectAttrs {
    let mut zeroize = true;

    if !attr.is_empty() {
        let parser = syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated;
        if let Ok(metas) = syn::parse::Parser::parse(parser, attr) {
            for meta in metas {
                if let Meta::NameValue(nv) = meta {
                    if nv.path.is_ident("zeroize") {
                        if let Expr::Lit(expr_lit) = &nv.value {
                            if let Lit::Bool(lit_bool) = &expr_lit.lit {
                                zeroize = lit_bool.value;
                            }
                        }
                    }
                }
            }
        }
    }

    ProtectAttrs { zeroize }
}
