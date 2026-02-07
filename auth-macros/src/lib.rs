use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

#[proc_macro_attribute]
pub fn db_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    let vis = &input.vis;
    let ident = &input.sig.ident;
    let block = &input.block;

    let expanded = quote! {
        #[tokio::test]
        #vis async fn #ident() {
            // bring the trait into scope inside the generated test
            use futures::FutureExt;

            let mut app = TestApp::new().await;

            let result = ::std::panic::AssertUnwindSafe(async {
                let app = &mut app;
                #block
            })
            .catch_unwind()
            .await;

            app.clean_up().await;

            if let ::std::result::Result::Err(panic) = result {
                ::std::panic::resume_unwind(panic);
            }
        }
    };

    expanded.into()
}

