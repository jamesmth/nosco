/// Configuration of execution tracing.
#[derive(Debug, PartialEq, knus::Decode)]
pub struct TraceConfig {
    /// Maximum function call depth.
    #[knus(child, default = 250, unwrap(argument))]
    pub call_depth: usize,

    /// Maximum backtrace depth.
    #[knus(child, default = 20, unwrap(argument))]
    pub backtrace_depth: usize,

    /// Scopes of execution tracing.
    #[knus(children(name = "trace"))]
    pub tracing_scopes: Vec<TraceScope>,
}

/// Configuration of scope for execution tracing.
#[derive(Debug, PartialEq, knus::Decode)]
pub struct TraceScope {
    /// Function symbol delimiting the start of the scope.
    #[knus(argument)]
    pub symbol: String,

    /// Binary containing the function symbol.
    #[knus(property)]
    pub binary: String,

    /// Maximum function call depth for this scope.
    #[knus(property)]
    pub call_depth: Option<usize>,
}

#[cfg(test)]
mod tests {

    use super::{TraceConfig, TraceScope};

    #[test]
    fn parse_from_kdl_no_scopes() {
        let config = knus::parse::<TraceConfig>("<content>", "")
            .map_err(miette::Report::new)
            .expect("parse kdl");

        assert_eq!(
            config,
            TraceConfig {
                call_depth: 250,
                backtrace_depth: 20,
                tracing_scopes: vec![],
            }
        );

        let config = knus::parse::<TraceConfig>(
            "<content>",
            indoc::indoc! {r#"
                call-depth 1
            "#},
        )
        .map_err(miette::Report::new)
        .expect("parse kdl");

        assert_eq!(
            config,
            TraceConfig {
                call_depth: 1,
                backtrace_depth: 20,
                tracing_scopes: vec![],
            }
        );

        let config = knus::parse::<TraceConfig>(
            "<content>",
            indoc::indoc! {r#"
                backtrace-depth 1
            "#},
        )
        .map_err(miette::Report::new)
        .expect("parse kdl");

        assert_eq!(
            config,
            TraceConfig {
                call_depth: 250,
                backtrace_depth: 1,
                tracing_scopes: vec![],
            }
        );
    }

    #[test]
    fn parse_from_kdl_with_scopes() {
        let config = knus::parse::<TraceConfig>(
            "<content>",
            indoc::indoc! {r#"
                trace "foo" binary="foo.so"
                trace "bar" binary="bar.so" call-depth=1
            "#},
        )
        .map_err(miette::Report::new)
        .expect("parse kdl");

        assert_eq!(
            config,
            TraceConfig {
                call_depth: 250,
                backtrace_depth: 20,
                tracing_scopes: vec![
                    TraceScope {
                        symbol: "foo".to_owned(),
                        binary: "foo.so".to_owned(),
                        call_depth: None
                    },
                    TraceScope {
                        symbol: "bar".to_owned(),
                        binary: "bar.so".to_owned(),
                        call_depth: Some(1),
                    },
                ]
            }
        );
    }
}
