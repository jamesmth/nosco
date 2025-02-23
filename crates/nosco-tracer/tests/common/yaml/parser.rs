use std::io::{BufReader, Read};

use libyaml_safer::{Encoding, Event, EventData, Parser};

use ouroboros::self_referencing;

use super::TraceEvent;

#[self_referencing]
struct YamlParser<R: 'static> {
    buffer: BufReader<R>,

    #[borrows(mut buffer)]
    #[not_covariant]
    parser: Parser<'this>,
}

impl<R: 'static> YamlParser<R> {
    fn parse(&mut self) -> super::Result<Event> {
        self.with_parser_mut(|parser| parser.parse().map_err(Into::into))
    }
}

pub struct HeaderParser<R: 'static> {
    parser: YamlParser<R>,
}

impl<R: Read + 'static> HeaderParser<R> {
    pub fn new(reader: R) -> Self {
        let parser = YamlParserBuilder {
            buffer: BufReader::new(reader),
            parser_builder: |buffer| {
                let mut parser = Parser::new();
                parser.set_input(buffer);
                parser.set_encoding(Encoding::Utf8);
                parser
            },
        }
        .build();

        Self { parser }
    }

    pub fn parse_header(mut self) -> super::Result<InitParser<R>> {
        assert!(matches!(
            self.parser.parse()?.data,
            EventData::StreamStart { .. }
        ));

        assert!(matches!(
            self.parser.parse()?.data,
            EventData::DocumentStart { .. }
        ));

        Ok(InitParser {
            parser: self.parser,
            expected: ExpectedEvent::MapStart,
        })
    }
}

pub struct FooterParser<R: 'static> {
    parser: YamlParser<R>,
}

impl<R: Read + 'static> FooterParser<R> {
    pub fn parse_footer(mut self) -> super::Result<()> {
        assert!(matches!(self.parser.parse()?.data, EventData::MappingEnd));
        assert!(matches!(
            self.parser.parse()?.data,
            EventData::DocumentEnd { .. }
        ));
        assert!(matches!(self.parser.parse()?.data, EventData::StreamEnd));
        Ok(())
    }
}

pub struct InitParser<R: 'static> {
    parser: YamlParser<R>,
    expected: ExpectedEvent,
}

impl<R: Read + 'static> InitParser<R> {
    pub fn next_event(&mut self) -> super::Result<Option<TraceEvent>> {
        loop {
            match self.expected {
                ExpectedEvent::MapStart => {
                    assert!(matches!(
                        self.parser.parse()?.data,
                        EventData::MappingStart { .. }
                    ));

                    let EventData::Scalar { value, .. } = self.parser.parse()?.data else {
                        panic!("invalid YAML");
                    };

                    assert_eq!(value, "init");

                    assert!(matches!(
                        self.parser.parse()?.data,
                        EventData::MappingStart { .. }
                    ));

                    let EventData::Scalar { value, .. } = self.parser.parse()?.data else {
                        panic!("invalid YAML");
                    };

                    assert_eq!(value, "loaded_binaries");

                    assert!(matches!(
                        self.parser.parse()?.data,
                        EventData::SequenceStart { .. }
                    ));

                    self.expected = ExpectedEvent::Scalar;
                }
                ExpectedEvent::Scalar => {
                    let scalar = match self.parser.parse()?.data {
                        EventData::Scalar { value, .. } => value,
                        EventData::SequenceEnd => {
                            self.expected = ExpectedEvent::End;
                            continue;
                        }
                        _ => panic!("invalid YAML"),
                    };

                    break Ok(Some(TraceEvent::StateInitBinaryLoaded { name: scalar }));
                }
                ExpectedEvent::End => {
                    assert!(matches!(self.parser.parse()?.data, EventData::MappingEnd));
                    break Ok(None);
                }
                _ => continue,
            }
        }
    }

    pub fn into_scope_parser(self) -> ScopeParser<R> {
        ScopeParser {
            parser: self.parser,
            expected: ExpectedEvent::Scalar,
            depth: 1,
        }
    }
}

pub struct ScopeParser<R: 'static> {
    parser: YamlParser<R>,
    expected: ExpectedEvent,

    depth: usize,
}

impl<R: Read + 'static> ScopeParser<R> {
    pub fn next_event(&mut self) -> super::Result<Option<TraceEvent>> {
        loop {
            if let ExpectedEvent::End = self.expected {
                break Ok(None);
            }

            match self.expected {
                ExpectedEvent::Scalar => {
                    let EventData::Scalar { value, .. } = self.parser.parse()?.data else {
                        panic!("invalid YAML");
                    };

                    assert_eq!(value, "trace");

                    self.expected = ExpectedEvent::SeqStart;
                }
                ExpectedEvent::SeqStart => {
                    assert!(matches!(
                        self.parser.parse()?.data,
                        EventData::SequenceStart { .. }
                    ));

                    self.expected = ExpectedEvent::MapStart;
                }
                ExpectedEvent::MapStart => {
                    if let Some(event) = self.parse_node()? {
                        break Ok(Some(event));
                    } else {
                        self.expected = ExpectedEvent::End;
                    }
                }
                _ => continue,
            }
        }
    }

    pub fn into_footer_parser(self) -> FooterParser<R> {
        FooterParser {
            parser: self.parser,
        }
    }

    fn parse_node(&mut self) -> super::Result<Option<TraceEvent>> {
        match self.parser.parse()?.data {
            EventData::MappingStart { .. } => (),
            EventData::SequenceEnd => {
                self.depth = self.depth.saturating_sub(1);

                if self.depth == 0 {
                    // end of main scope, no nodes left to parse
                    return Ok(None);
                } else {
                    // expect an end-of-scope
                    assert!(matches!(self.parser.parse()?.data, EventData::MappingEnd));

                    return Ok(Some(TraceEvent::FnReturn));
                }
            }
            _ => panic!("invalid YAML"),
        }

        let EventData::Scalar { value: key, .. } = self.parser.parse()?.data else {
            panic!("invalid YAML");
        };

        let event = match self.parser.parse()?.data {
            EventData::Scalar { value, .. } => {
                let trace_event = match key.as_ref() {
                    "loaded" => TraceEvent::StateUpdateBinaryLoaded { name: value },
                    "unloaded" => TraceEvent::StateUpdateBinaryUnloaded { name: value },
                    _ => {
                        let offset = u64::from_str_radix(key.trim_start_matches("0x"), 16)?;
                        TraceEvent::Exec { offset, asm: value }
                    }
                };

                assert!(matches!(self.parser.parse()?.data, EventData::MappingEnd));

                trace_event
            }
            EventData::SequenceStart { .. } => {
                self.depth += 1;
                TraceEvent::FnCall { name: key }
            }
            _ => panic!("invalid YAML"),
        };

        self.expected = ExpectedEvent::MapStart;

        Ok(Some(event))
    }
}

#[derive(Debug)]
enum ExpectedEvent {
    SeqStart,
    MapStart,
    Scalar,
    End,
}
