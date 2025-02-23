use std::fs::File;
use std::io::Read;
use std::mem;
use std::path::Path;

use super::parser::{FooterParser, HeaderParser, InitParser, ScopeParser};
use super::TraceEvent;

enum ParserState<R: 'static> {
    Header(HeaderParser<R>),
    TraceInit(InitParser<R>),
    TraceBody(ScopeParser<R>),
    Footer(FooterParser<R>),
    End,
}

pub struct YamlStream<R: 'static> {
    parser_state: ParserState<R>,
}

impl YamlStream<File> {
    pub fn from_path(path: impl AsRef<Path>) -> super::Result<Self> {
        File::open(path).map(Self::from_reader).map_err(Into::into)
    }
}

impl<R: Read + 'static> YamlStream<R> {
    pub fn from_reader(reader: R) -> Self {
        let header_parser = HeaderParser::new(reader);
        let parser_state = ParserState::Header(header_parser);

        Self { parser_state }
    }

    fn next_event(&mut self) -> super::Result<Option<TraceEvent>> {
        loop {
            match mem::replace(&mut self.parser_state, ParserState::End) {
                ParserState::Header(parser) => {
                    let parser = parser.parse_header()?;
                    self.parser_state = ParserState::TraceInit(parser);
                }
                ParserState::TraceInit(mut parser) => {
                    if let Some(event) = parser.next_event()? {
                        self.parser_state = ParserState::TraceInit(parser);
                        break Ok(Some(event));
                    } else {
                        self.parser_state = ParserState::TraceBody(parser.into_scope_parser());
                    }
                }
                ParserState::TraceBody(mut parser) => {
                    if let Some(event) = parser.next_event()? {
                        self.parser_state = ParserState::TraceBody(parser);
                        break Ok(Some(event));
                    } else {
                        self.parser_state = ParserState::Footer(parser.into_footer_parser());
                    }
                }
                ParserState::Footer(parser) => {
                    parser.parse_footer()?;
                    self.parser_state = ParserState::End;
                }
                ParserState::End => break Ok(None),
            }
        }
    }
}

impl<R: Read> Iterator for YamlStream<R> {
    type Item = super::Result<TraceEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_event().transpose()
    }
}
