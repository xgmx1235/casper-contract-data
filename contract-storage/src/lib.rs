use proc_macro::TokenStream;
use proc_macro2::{Ident as Ident2, TokenStream as TokenStream2};
use quote::{quote, TokenStreamExt, format_ident, ToTokens};
use syn::{parse_macro_input, Data, DataStruct, DeriveInput, Fields, Field};
use convert_case::{ Case, Casing };

enum NamedField {
    NamedFieldSimple(NamedFieldSimple),
    NamedFieldMapping(NamedFieldMapping),
    NamedFieldNestedMapping(NamedFieldNestedMapping),
    NamedFieldNestedNestedMapping(NamedFieldNestedNestedMapping),
}

#[derive(Clone)]
struct NamedFieldSimple {
    pub name: Ident2,
    pub ty: Ident2,
}

#[derive(Clone)]
struct NamedFieldMapping {
    pub name: Ident2,
    pub ty1: Ident2,
    pub ty2: Ident2,
}

#[derive(Clone)]
struct NamedFieldNestedMapping {
    pub name: Ident2,
    pub ty1: Ident2,
    pub ty2: Ident2,
    pub ty3: Ident2,
}

#[derive(Clone)]
struct NamedFieldNestedNestedMapping {
    pub name: Ident2,
    pub ty1: Ident2,
    pub ty2: Ident2,
    pub ty3: Ident2,
    pub ty4: Ident2,
}

fn to_named_field(x: Field) -> NamedField {
    let name = x.clone().ident.unwrap();
    let type_tokens = x.ty.to_token_stream().into_iter().collect::<Vec<_>>();
    if type_tokens[0].to_string() == "Mapping" {
        NamedField::NamedFieldMapping(NamedFieldMapping {
            name,
            ty1: format_ident!("{}", type_tokens[2].to_string()),
            ty2: format_ident!("{}", type_tokens[4].to_string()),
        })
    } else if type_tokens[0].to_string() == "NestedMapping" {
        NamedField::NamedFieldNestedMapping(NamedFieldNestedMapping {
            name,
            ty1: format_ident!("{}", type_tokens[2].to_string()),
            ty2: format_ident!("{}", type_tokens[4].to_string()),
            ty3: format_ident!("{}", type_tokens[6].to_string()),
        })
    } else if type_tokens[0].to_string() == "NestedNestedMapping" {
        NamedField::NamedFieldNestedNestedMapping(NamedFieldNestedNestedMapping {
            name,
            ty1: format_ident!("{}", type_tokens[2].to_string()),
            ty2: format_ident!("{}", type_tokens[4].to_string()),
            ty3: format_ident!("{}", type_tokens[6].to_string()),
            ty4: format_ident!("{}", type_tokens[8].to_string()),
        })
    } else {
        NamedField::NamedFieldSimple(NamedFieldSimple { name, ty: format_ident!("{}", type_tokens[0].to_string()) })
    }
}

fn named_fields(input: DeriveInput) -> Result<Vec<NamedField>, TokenStream> {
    let fields = match input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(named_fields),
            ..
        }) => named_fields
            .named
            .into_iter()
            .map(|x| to_named_field(x) )
            .collect::<Vec<_>>(),
        _ => {
            return Err(TokenStream::from(
                quote! { compile_error!("Expected a struct with named fields."); },
            ))
        }
    };
    Ok(fields)
}

#[proc_macro_derive(InitializeStorage)]
pub fn derive_initialize_storage(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_ident = input.ident.clone();
    let fields = match named_fields(input) {
        Ok(fields) => fields,
        Err(error_stream) => return error_stream,
    };

    let mut deserialize_fields = TokenStream2::new();
    deserialize_fields.append_all(fields.iter().map(|ident| {
        match ident {
            NamedField::NamedFieldSimple(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                let func_save_name = format_ident!("save_{}", param_name_str);
                let func_read_name = format_ident!("read_{}", param_name_str);
                let type_name = format_ident!("{}", ident.ty.to_string());
                let param_name: Ident2 = format_ident!("_{}", ident.name.to_string());
                quote! {
                    pub fn #func_initialize_name() {
                        helpers::set_key(#param_name_str, #type_name::default());
                    }

                    pub fn #func_save_name(#param_name: #type_name) {
                        helpers::set_key(#param_name_str, #param_name);
                    }

                    pub fn #func_read_name() -> #type_name {
                        helpers::get_key(#param_name_str).unwrap_or_default()
                    }
                }
            },
            NamedField::NamedFieldMapping(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                let func_save_name = format_ident!("save_{}", param_name_str);
                let func_read_name = format_ident!("read_{}", param_name_str);
                let key_type_name = format_ident!("{}", ident.ty1.to_string());
                let value_type_name = format_ident!("{}", ident.ty2.to_string());
                let param_name: Ident2 = format_ident!("_{}", ident.name.to_string());
                quote! {
                    pub fn #func_initialize_name() {
                        storage::new_dictionary(#param_name_str)
                                        .unwrap_or_revert_with(Error::FailedToCreateDictionary);
                    }

                    pub fn #func_save_name(k: &#key_type_name, #param_name: &#value_type_name) {
                        let encoded = helpers::encode_1(k);
                        let bytes = runtime::blake2b(encoded);
                        let k = hex::encode(bytes);
                        helpers::write_dictionary_value_from_key(#param_name_str, &k, #param_name.clone());
                    }

                    pub fn #func_read_name(k: &#key_type_name) -> #value_type_name {
                        let encoded = helpers::encode_1(k);
                        let bytes = runtime::blake2b(encoded);
                        let k = hex::encode(bytes);
                        helpers::get_dictionary_value_from_key(#param_name_str, &k).unwrap_or_default()
                    }
                }
            },
            NamedField::NamedFieldNestedMapping(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                let func_save_name = format_ident!("save_{}", param_name_str);
                let func_read_name = format_ident!("read_{}", param_name_str);
                let key1_type_name = format_ident!("{}", ident.ty1.to_string());
                let key2_type_name = format_ident!("{}", ident.ty2.to_string());
                let value_type_name = format_ident!("{}", ident.ty3.to_string());
                let param_name: Ident2 = format_ident!("_{}", ident.name.to_string());
                quote! {
                    pub fn #func_initialize_name() {
                        storage::new_dictionary(#param_name_str)
                                        .unwrap_or_revert_with(Error::FailedToCreateDictionary);
                    }

                    pub fn #func_save_name(k1: &#key1_type_name, k2: &#key2_type_name, #param_name: &#value_type_name) {
                        let encoded = helpers::encode_2(k1, k2);
                        let bytes = runtime::blake2b(encoded);
                        let k = hex::encode(bytes);
                        helpers::write_dictionary_value_from_key(#param_name_str, &k, #param_name.clone());
                    }

                    pub fn #func_read_name(k1: &#key1_type_name, k2: &#key2_type_name) -> #value_type_name {
                        let encoded = helpers::encode_2(k1, k2);
                        let bytes = runtime::blake2b(encoded);
                        let k = hex::encode(bytes);
                        helpers::get_dictionary_value_from_key(#param_name_str, &k).unwrap_or_default()
                    }
                }
            },
            NamedField::NamedFieldNestedNestedMapping(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                let func_save_name = format_ident!("save_{}", param_name_str);
                let func_read_name = format_ident!("read_{}", param_name_str);
                let key1_type_name = format_ident!("{}", ident.ty1.to_string());
                let key2_type_name = format_ident!("{}", ident.ty2.to_string());
                let key3_type_name = format_ident!("{}", ident.ty3.to_string());
                let value_type_name = format_ident!("{}", ident.ty4.to_string());
                let param_name: Ident2 = format_ident!("_{}", ident.name.to_string());
                quote! {
                    pub fn #func_initialize_name() {
                        storage::new_dictionary(#param_name_str)
                                        .unwrap_or_revert_with(Error::FailedToCreateDictionary);
                    }

                    pub fn #func_save_name(k1: &#key1_type_name, k2: &#key2_type_name, k3: &#key3_type_name, #param_name: &#value_type_name) {
                        let encoded = helpers::encode_3(k1, k2, k3);
                        let bytes = runtime::blake2b(encoded);
                        let k = hex::encode(bytes);
                        helpers::write_dictionary_value_from_key(#param_name_str, &k, #param_name.clone());
                    }

                    pub fn #func_read_name(k1: &#key1_type_name, k2: &#key2_type_name, k3: &#key3_type_name) -> #value_type_name {
                        let encoded = helpers::encode_3(k1, k2, k3);
                        let bytes = runtime::blake2b(encoded);
                        let k = hex::encode(bytes);
                        helpers::get_dictionary_value_from_key(#param_name_str, &k).unwrap_or_default()
                    }
                }
            }
        }
    }));

    let mut call_to_initialize_fields = TokenStream2::new();
    call_to_initialize_fields.append_all(fields.iter().map(|ident| {
        match ident {
            NamedField::NamedFieldSimple(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                quote! {
                    #func_initialize_name();
                }
            },
            NamedField::NamedFieldMapping(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                quote! {
                    #func_initialize_name();
                }
            },
            NamedField::NamedFieldNestedMapping(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                quote! {
                    #func_initialize_name();
                }
            },
            NamedField::NamedFieldNestedNestedMapping(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                quote! {
                    #func_initialize_name();
                }
            }
        }
    }));

    let initialize_struct_func_name_ident = format_ident!("initialize_data_{}", struct_ident.to_string().to_case(Case::Snake));
    let expanded = quote! {
        #deserialize_fields
        pub fn #initialize_struct_func_name_ident () {
            #call_to_initialize_fields
        }
    };

    TokenStream::from(expanded)
}

// #[proc_macro_derive(Getter)]
// pub fn derive_from_bytes(input: TokenStream) -> TokenStream {
//   let input = parse_macro_input!(input as DeriveInput);
//   let struct_ident = input.ident.clone();
//   let fields = match named_fields(input) {
//     Ok(fields) => fields,
//     Err(error_stream) => return error_stream,
//   };

//   let mut deserialize_fields = TokenStream2::new();
//   deserialize_fields.append_all(fields.iter().map(|ident| {
//     quote! {
//       let (#ident, bytes) = casper_types::bytesrepr::FromBytes::from_bytes(bytes)?;
//     }
//   }));

//   let mut construct_struct = TokenStream2::new();
//   construct_struct.append_all(fields.iter().map(|ident| quote! { #ident, }));

//   let expanded = quote! {
//     impl casper_types::bytesrepr::FromBytes for #struct_ident {
//       fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
//         #deserialize_fields
//         let value = #struct_ident {
//           #construct_struct
//         };
//         Ok((value, bytes))
//       }
//     }
//   };

//   TokenStream::from(expanded)
// }

// #[proc_macro_derive(ToBytes)]
// pub fn derive_to_bytes(input: TokenStream) -> TokenStream {
//   let input = parse_macro_input!(input as DeriveInput);
//   let struct_ident = input.ident.clone();
//   let fields = match named_fields(input) {
//     Ok(fields) => fields,
//     Err(error_stream) => return error_stream,
//   };

//   let mut sum_serialized_lengths = TokenStream2::new();
//   sum_serialized_lengths.append_all(fields.iter().map(|ident| {
//     quote! {
//       size += self.#ident.serialized_length();
//     }
//   }));

//   let mut append_bytes = TokenStream2::new();
//   append_bytes.append_all(fields.iter().map(|ident| {
//     quote! {
//       vec.extend(self.#ident.to_bytes()?);
//     }
//   }));

//   let expanded = quote! {
//     impl casper_types::bytesrepr::ToBytes for #struct_ident {
//       fn serialized_length(&self) -> usize {
//         let mut size = 0;
//         #sum_serialized_lengths
//         return size;
//       }

//       fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
//         let mut vec = Vec::with_capacity(self.serialized_length());
//         #append_bytes
//         Ok(vec)
//       }
//     }
//   };

//   TokenStream::from(expanded)
// }
