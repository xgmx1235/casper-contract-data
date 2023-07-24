use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::{Ident as Ident2, TokenStream as TokenStream2};
use quote::{format_ident, quote, ToTokens, TokenStreamExt};
use syn::{parse_macro_input, Data, DataStruct, DeriveInput, Field, Fields};

enum NamedField {
    Simple(NamedFieldSimple),
    Mapping(NamedFieldMapping),
    NestedMapping(NamedFieldNestedMapping),
    NestedNestedMapping(NamedFieldNestedNestedMapping),
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
        NamedField::Mapping(NamedFieldMapping {
            name,
            ty1: format_ident!("{}", type_tokens[2].to_string()),
            ty2: format_ident!("{}", type_tokens[4].to_string()),
        })
    } else if type_tokens[0].to_string() == "NestedMapping" {
        NamedField::NestedMapping(NamedFieldNestedMapping {
            name,
            ty1: format_ident!("{}", type_tokens[2].to_string()),
            ty2: format_ident!("{}", type_tokens[4].to_string()),
            ty3: format_ident!("{}", type_tokens[6].to_string()),
        })
    } else if type_tokens[0].to_string() == "NestedNestedMapping" {
        NamedField::NestedNestedMapping(NamedFieldNestedNestedMapping {
            name,
            ty1: format_ident!("{}", type_tokens[2].to_string()),
            ty2: format_ident!("{}", type_tokens[4].to_string()),
            ty3: format_ident!("{}", type_tokens[6].to_string()),
            ty4: format_ident!("{}", type_tokens[8].to_string()),
        })
    } else {
        NamedField::Simple(NamedFieldSimple {
            name,
            ty: format_ident!("{}", type_tokens[0].to_string()),
        })
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
            .map(to_named_field)
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
            NamedField::Simple(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                let func_save_name = format_ident!("save_{}", param_name_str);
                let func_read_name = format_ident!("read_{}", param_name_str);
                let func_get_name = format_ident!("get_{}", param_name_str);
                let func_get_ep_name = format_ident!("get_{}_entry_point", param_name_str);
                let func_get_ep_name_str = func_get_name.to_string();
                let type_name = format_ident!("{}", ident.ty.to_string());
                let param_name: Ident2 = format_ident!("_{}", ident.name.to_string());
                quote! {
                    pub fn #func_initialize_name() {
                        // helpers::set_key(#param_name_str, #type_name::default());
                    }

                    pub fn #func_save_name(#param_name: #type_name) {
                        helpers::set_key(#param_name_str, #param_name);
                    }

                    pub fn #func_read_name() -> #type_name {
                        helpers::get_key(#param_name_str).unwrap_or_revert()
                    }

                    #[no_mangle]
                    pub extern "C" fn #func_get_name() {
                        runtime::ret(CLValue::from_t(#func_read_name()).unwrap_or_revert())
                    }

                    pub fn #func_get_ep_name() -> EntryPoint {
                        EntryPoint::new(
                            String::from(#func_get_ep_name_str),
                            vec![],
                            #type_name::cl_type(),
                            EntryPointAccess::Public,
                            EntryPointType::Contract,
                        )
                    }
                }
            },
            NamedField::Mapping(ident) => {
                let param_name_str = ident.name.to_string();
                let func_initialize_name = format_ident!("initialize_{}", param_name_str);
                let func_save_name = format_ident!("save_{}", param_name_str);
                let func_read_name = format_ident!("read_{}", param_name_str);
                let key_type_name = format_ident!("{}", ident.ty1.to_string());
                let value_type_name = format_ident!("{}", ident.ty2.to_string());
                let param_name: Ident2 = format_ident!("_{}", ident.name.to_string());
                let func_get_name = format_ident!("get_{}", param_name_str);
                let func_get_ep_name = format_ident!("get_{}_entry_point", param_name_str);
                let func_get_ep_name_str = func_get_name.to_string();
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

                    #[no_mangle]
                    pub extern "C" fn #func_get_name() {
                        let #param_name: #key_type_name = runtime::get_named_arg(#param_name_str);
                        runtime::ret(CLValue::from_t(#func_read_name(&#param_name)).unwrap_or_revert())
                    }

                    pub fn #func_get_ep_name() -> EntryPoint {
                        EntryPoint::new(
                            String::from(#func_get_ep_name_str),
                            vec![Parameter::new(#param_name_str, #key_type_name::cl_type())],
                            #value_type_name::cl_type(),
                            EntryPointAccess::Public,
                            EntryPointType::Contract,
                        )
                    }
                }
            },
            NamedField::NestedMapping(ident) => {
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
            NamedField::NestedNestedMapping(ident) => {
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
    call_to_initialize_fields.append_all(fields.iter().map(|ident| match ident {
        NamedField::Simple(ident) => {
            let param_name_str = ident.name.to_string();
            let func_initialize_name = format_ident!("initialize_{}", param_name_str);
            quote! {
                #func_initialize_name();
            }
        }
        NamedField::Mapping(ident) => {
            let param_name_str = ident.name.to_string();
            let func_initialize_name = format_ident!("initialize_{}", param_name_str);
            quote! {
                #func_initialize_name();
            }
        }
        NamedField::NestedMapping(ident) => {
            let param_name_str = ident.name.to_string();
            let func_initialize_name = format_ident!("initialize_{}", param_name_str);
            quote! {
                #func_initialize_name();
            }
        }
        NamedField::NestedNestedMapping(ident) => {
            let param_name_str = ident.name.to_string();
            let func_initialize_name = format_ident!("initialize_{}", param_name_str);
            quote! {
                #func_initialize_name();
            }
        }
    }));

    let initialize_struct_func_name_ident = format_ident!(
        "initialize_data_{}",
        struct_ident.to_string().to_case(Case::Snake)
    );

    let mut call_get_entry_points_getters = TokenStream2::new();
    call_get_entry_points_getters.append_all(fields.iter().map(|ident| match ident {
        NamedField::Simple(ident) => {
            let param_name_str = ident.name.to_string();
            let func_get_ep_name = format_ident!("get_{}_entry_point", param_name_str);
            quote! {
                #func_get_ep_name(),
            }
        }
        NamedField::Mapping(ident) => {
            let param_name_str = ident.name.to_string();
            let func_get_ep_name = format_ident!("get_{}_entry_point", param_name_str);
            quote! {
                #func_get_ep_name(),
            }
        }
        NamedField::NestedMapping(ident) => {
            let param_name_str = ident.name.to_string();
            let func_get_ep_name = format_ident!("get_{}_entry_point", param_name_str);
            quote! {
                #func_get_ep_name(),
            }
        }
        NamedField::NestedNestedMapping(ident) => {
            let param_name_str = ident.name.to_string();
            let func_get_ep_name = format_ident!("get_{}_entry_point", param_name_str);
            quote! {
                #func_get_ep_name(),
            }
        }
    }));

    // getter entry points
    let getter_entry_points_func_name_ident = format_ident!(
        "getters_entry_points_for_{}",
        struct_ident.to_string().to_case(Case::Snake)
    );

    let expanded = quote! {
        #deserialize_fields
        pub fn #initialize_struct_func_name_ident () {
            #call_to_initialize_fields
        }

        pub fn #getter_entry_points_func_name_ident () -> Vec<EntryPoint> {
            vec![
                #call_get_entry_points_getters
            ]
        }
    };

    TokenStream::from(expanded)
}
