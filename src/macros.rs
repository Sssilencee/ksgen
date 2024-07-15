#[macro_export]
macro_rules! unwrap_or_handle {
    ($res:expr $(,)?) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                return CString::new(e.to_string())
                    .expect("CString::new() failed")
                    .into_raw();
            }
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_handle_ctx {
    ($res:expr, $ctx:expr $(,)?) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                return CString::new(format!("{}: {}", $ctx, e))
                    .expect("CString::new() failed")
                    .into_raw();
            }
        }
    };
}

#[macro_export]
macro_rules! bail {
    ($msg:expr, $($arg:expr)+ $(,)?) => {
        return CString::new(format!($msg, $($arg)*))
            .expect("CString::new() failed")
            .into_raw()
    };
}