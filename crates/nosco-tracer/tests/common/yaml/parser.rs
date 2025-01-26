use std::io::Read;

use serde_yml::libyml::parser::{Event, MappingStart, Scalar, ScalarStyle, SequenceStart};
use serde_yml::libyml::tag::Tag;
use serde_yml::libyml::util::Owned;

use super::TraceEvent;

pub struct HeaderParser<R: Read> {
    parser: YamlParser<R>,
    expected: ExpectedEvent,
}

impl<R: Read> HeaderParser<R> {
    pub const fn new(parser: YamlParser<R>) -> Self {
        Self {
            parser,
            expected: ExpectedEvent::StreamStart,
        }
    }

    pub fn parse_header(mut self) -> super::Result<ScopeParser<R>> {
        loop {
            let event = self.parser.parse_next_event()?;

            match (&self.expected, event) {
                (ExpectedEvent::StreamStart, Event::StreamStart) => {
                    self.expected = ExpectedEvent::DocStart
                }
                (ExpectedEvent::DocStart, Event::DocumentStart) => {
                    break Ok(ScopeParser {
                        parser: self.parser,
                        expected: ExpectedEvent::SeqStart,
                        depth: 1,
                    })
                }
                _ => panic!("invalid YAML"),
            }
        }
    }
}

pub struct FooterParser<R: Read> {
    parser: YamlParser<R>,
    expected: ExpectedEvent,
}

impl<R: Read> FooterParser<R> {
    pub fn parse_footer(mut self) -> super::Result<()> {
        loop {
            let event = self.parser.parse_next_event()?;

            match (&self.expected, event) {
                (ExpectedEvent::DocEnd, Event::DocumentEnd) => {
                    self.expected = ExpectedEvent::StreamEnd
                }
                (ExpectedEvent::StreamEnd, Event::StreamEnd) => {
                    break Ok(());
                }
                t => panic!("invalid YAML: {t:?}"),
            }
        }
    }
}

pub struct ScopeParser<R: Read> {
    parser: YamlParser<R>,
    expected: ExpectedEvent,

    depth: usize,
}

impl<R: Read> ScopeParser<R> {
    pub fn next_event(&mut self) -> super::Result<Option<TraceEvent>> {
        loop {
            if let ExpectedEvent::End = self.expected {
                break Ok(None);
            }

            match self.expected {
                ExpectedEvent::SeqStart => {
                    let event = self.parser.parse_next_event()?;
                    if !matches!(event, Event::SequenceStart(_)) {
                        panic!("invalid YAML");
                    }

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
            expected: ExpectedEvent::DocEnd,
        }
    }

    fn parse_node(&mut self) -> super::Result<Option<TraceEvent>> {
        match self.parser.parse_next_event()? {
            Event::MappingStart(_) => (),
            Event::SequenceEnd => {
                self.depth = self.depth.saturating_sub(1);

                if self.depth == 0 {
                    // end of main scope, no nodes left to parse
                    return Ok(None);
                } else {
                    // expect an end-of-scope
                    let Event::MappingEnd = self.parser.parse_next_event()? else {
                        panic!("invalid YAML");
                    };

                    return Ok(Some(TraceEvent::FnReturn));
                }
            }
            _ => panic!("invalid YAML"),
        }

        let Event::Scalar(scalar) = self.parser.parse_next_event()? else {
            panic!("invalid YAML");
        };

        let node_key = scalar.value;

        let event = match self.parser.parse_next_event()? {
            Event::Scalar(scalar) => {
                let node_val = scalar.value;

                let offset = String::from_utf8_lossy(&node_key);
                let offset = u64::from_str_radix(offset.trim_start_matches("0x"), 16)?;

                let asm = String::from_utf8_lossy(&node_val).into_owned();

                let Event::MappingEnd = self.parser.parse_next_event()? else {
                    panic!("invalid YAML");
                };

                TraceEvent::Exec { offset, asm }
            }
            Event::SequenceStart(_) => {
                let name = String::from_utf8_lossy(&node_key).into_owned();

                self.depth += 1;

                TraceEvent::FnCall { name }
            }
            _ => panic!("invalid YAML"),
        };

        self.expected = ExpectedEvent::MapStart;

        Ok(Some(event))
    }
}

#[derive(Debug)]
enum ExpectedEvent {
    StreamStart,
    StreamEnd,
    DocStart,
    DocEnd,
    SeqStart,
    MapStart,
    End,
}

pub struct YamlParser<R> {
    pub pin: Owned<libyml::YamlParserT>,
    reader: *mut YamlReadHandlerData<R>,
}

impl<R: Read> YamlParser<R> {
    pub fn init(reader: R) -> super::Result<Self> {
        let owned = Owned::<libyml::YamlParserT>::new_uninit();

        let (pin, reader) = unsafe {
            let parser = std::ptr::addr_of_mut!(*owned.ptr);
            if libyml::yaml_parser_initialize(parser).fail {
                return Err(super::Error::Yaml(
                    serde_yml::libyml::error::Error::parse_error(parser),
                ));
            }

            libyml::yaml_parser_set_encoding(parser, libyml::YamlUtf8Encoding);

            let data = Box::into_raw(Box::new(YamlReadHandlerData { reader }));

            libyml::yaml_parser_set_input(parser, Self::read_handler, data.cast());

            (Owned::assume_init(owned), data)
        };

        Ok(Self { pin, reader })
    }

    pub fn parse_next_event(&mut self) -> super::Result<Event> {
        let mut event = std::mem::MaybeUninit::<libyml::YamlEventT>::uninit();

        unsafe {
            let parser = std::ptr::addr_of_mut!(*self.pin.ptr);
            if (*parser).error != libyml::YamlNoError {
                return Err(super::Error::Yaml(
                    serde_yml::libyml::error::Error::parse_error(parser),
                ));
            }

            let event = event.as_mut_ptr();
            if libyml::yaml_parser_parse(parser, event).fail {
                return Err(super::Error::Yaml(
                    serde_yml::libyml::error::Error::parse_error(parser),
                ));
            }

            let event_type = (*event).type_;

            // Handle specific cases
            if event_type == libyml::YamlNoEvent || event_type == libyml::YamlStreamEndEvent {
                libyml::yaml_event_delete(event);
                return Ok(Event::StreamEnd);
            }

            if event_type == libyml::YamlScalarEvent && (*event).data.scalar.value.is_null() {
                libyml::yaml_event_delete(event);
                return Ok(Event::StreamEnd);
            }

            let ret = convert_event(&*event);

            libyml::yaml_event_delete(event);

            Ok(ret)
        }
    }

    unsafe fn read_handler(
        data: *mut std::ffi::c_void,
        buffer: *mut std::ffi::c_uchar,
        size: u64,
        size_read: *mut u64,
    ) -> std::ffi::c_int {
        let mut data = Box::<YamlReadHandlerData<R>>::from_raw(data.cast());

        let len = size as usize;
        let buf = std::slice::from_raw_parts_mut(buffer.cast::<u8>(), len);

        let ret = match data.reader.read(buf) {
            Ok(n) => {
                *size_read = n as u64;
                1
            }
            Err(_) => 0,
        };

        let _ = Box::into_raw(data);
        ret
    }
}

impl<R> Drop for YamlParser<R> {
    fn drop(&mut self) {
        let _ = unsafe { Box::from_raw(self.reader) };
    }
}

struct YamlReadHandlerData<R> {
    reader: R,
}

unsafe fn convert_event(sys: &libyml::YamlEventT) -> Event<'static> {
    match sys.type_ {
        libyml::YamlStreamStartEvent => Event::StreamStart,
        libyml::YamlStreamEndEvent => Event::StreamEnd,
        libyml::YamlDocumentStartEvent => Event::DocumentStart,
        libyml::YamlDocumentEndEvent => Event::DocumentEnd,
        libyml::YamlAliasEvent => unimplemented!("YAML alias unsupported"),
        libyml::YamlScalarEvent => {
            let value_slice =
                std::slice::from_raw_parts(sys.data.scalar.value, sys.data.scalar.length as usize);

            Event::Scalar(Scalar {
                anchor: None,
                tag: optional_tag(sys.data.scalar.tag),
                value: Box::from(value_slice),
                style: match sys.data.scalar.style {
                    libyml::YamlScalarStyleT::YamlPlainScalarStyle => ScalarStyle::Plain,
                    libyml::YamlScalarStyleT::YamlSingleQuotedScalarStyle => {
                        ScalarStyle::SingleQuoted
                    }
                    libyml::YamlScalarStyleT::YamlDoubleQuotedScalarStyle => {
                        ScalarStyle::DoubleQuoted
                    }
                    libyml::YamlScalarStyleT::YamlLiteralScalarStyle => ScalarStyle::Literal,
                    libyml::YamlScalarStyleT::YamlFoldedScalarStyle => ScalarStyle::Folded,
                    _ => unreachable!(),
                },
                repr: None,
            })
        }
        libyml::YamlSequenceStartEvent => Event::SequenceStart(SequenceStart {
            anchor: None,
            tag: optional_tag(sys.data.sequence_start.tag),
        }),
        libyml::YamlSequenceEndEvent => Event::SequenceEnd,
        libyml::YamlMappingStartEvent => Event::MappingStart(MappingStart {
            anchor: None,
            tag: optional_tag(sys.data.mapping_start.tag),
        }),
        libyml::YamlMappingEndEvent => Event::MappingEnd,
        libyml::YamlNoEvent => unreachable!(),
        _ => unreachable!(),
    }
}

unsafe fn optional_tag(tag: *const u8) -> Option<Tag> {
    if tag.is_null() {
        return None;
    }

    let ptr = std::ptr::NonNull::new(tag as *mut i8)?;
    let cstr = serde_yml::libyml::safe_cstr::CStr::from_ptr(ptr);

    std::str::from_utf8(cstr.to_bytes()).ok().map(Tag::new)
}
