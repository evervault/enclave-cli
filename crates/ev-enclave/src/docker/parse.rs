use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::StreamExt;
use itertools::join;
use std::convert::{From, TryFrom, TryInto};
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio_util::codec::{Decoder, FramedRead};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delimiter {
    Eq,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Exec,
    Shell,
}

impl Mode {
    pub fn is_shell(&self) -> bool {
        matches!(self, Self::Shell)
    }

    pub fn is_exec(&self) -> bool {
        matches!(self, Self::Exec)
    }
}

impl From<u8> for Mode {
    fn from(byte: u8) -> Self {
        if byte == b'[' {
            Self::Exec
        } else {
            Self::Shell
        }
    }
}

#[derive(Clone, Debug)]
pub struct EnvVar {
    pub key: String,
    pub val: String,
    pub delim: Delimiter,
}

impl Display for EnvVar {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.delim {
            Delimiter::Eq => write!(f, "{}={}", self.key, self.val)?,
            Delimiter::None => write!(f, "{} {}", self.key, self.val)?,
        };
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum Directive {
    Add {
        source_url: String,
        destination_path: String,
    },
    Comment(Bytes),
    Entrypoint {
        mode: Option<Mode>,
        tokens: Vec<String>,
    },
    Cmd {
        mode: Option<Mode>,
        tokens: Vec<String>,
    },
    Expose {
        port: Option<u16>,
    },
    Run(Bytes),
    User(Bytes),
    Env {
        vars: Vec<EnvVar>,
    },
    Other {
        directive: String,
        arguments: Bytes,
    },
    From {
        arguments: Bytes,
    },
}

impl Directive {
    pub fn is_cmd(&self) -> bool {
        matches!(self, Self::Cmd { .. })
    }

    pub fn is_entrypoint(&self) -> bool {
        matches!(self, Self::Entrypoint { .. })
    }

    pub fn is_expose(&self) -> bool {
        matches!(self, Self::Expose { .. })
    }

    #[allow(dead_code)]
    pub fn is_run(&self) -> bool {
        matches!(self, Self::Run(_))
    }

    pub fn is_user(&self) -> bool {
        matches!(self, Self::User(_))
    }

    pub fn is_env(&self) -> bool {
        matches!(self, Self::Env { .. })
    }

    pub fn is_from(&self) -> bool {
        matches!(self, Self::From { .. })
    }

    pub fn set_mode(&mut self, new_mode: Mode) {
        match self {
            Self::Entrypoint { mode, .. } | Self::Cmd { mode, .. } => {
                *mode = Some(new_mode);
            }
            _ => panic!("Attempt to set mode on directive which is not Entrypoint or Cmd"),
        }
    }

    pub fn mode(&self) -> Option<&Mode> {
        match self {
            Self::Entrypoint { mode, .. } | Self::Cmd { mode, .. } => mode.as_ref(),
            _ => None,
        }
    }

    fn extract_tokens_for_env_directive(directive: String) -> (Vec<String>, Delimiter) {
        let mut in_quotes = false;
        let mut escape = false;
        let mut current_token = String::new();
        let mut tokens = Vec::new();
        let mut delim = Delimiter::None;

        for c in directive.chars() {
            match c {
                '\\' if escape => {
                    escape = false;
                    current_token.push(c);
                }
                '\\' if !escape => {
                    escape = true;
                }
                '"' => {
                    in_quotes = !in_quotes;
                    current_token.push(c);
                }
                ' ' if in_quotes => {
                    current_token.push(c);
                }
                ' ' if !in_quotes => {
                    if !current_token.is_empty() {
                        tokens.push(current_token.trim().to_string());
                        current_token = String::new();
                    }
                }
                '=' if !in_quotes && !escape => {
                    current_token.push(c);
                    delim = Delimiter::Eq;
                }
                _ => current_token.push(c),
            }
        }

        if !current_token.is_empty() {
            tokens.push(current_token.trim().to_string());
        }

        (tokens, delim)
    }

    fn parse_env_directive(directive: String) -> Result<Vec<EnvVar>, DecodeError> {
        let (tokens, delim) = Self::extract_tokens_for_env_directive(directive);

        // ENV directive's do not have to contain an "="
        // `ENV HELLO WORLD` is the same as `ENV HELLO=WORLD`
        // However you must use an = if you want to assign multiple env vars on one line
        // https://docs.docker.com/engine/reference/builder/#env

        // If delimiter is none, then the first token is assumed to be the key, with all subsequent tokens as a single string value
        if delim == Delimiter::None {
            if tokens.len() < 2 {
                return Err(DecodeError::IncompleteInstruction);
            }
            let (key, values) = tokens.split_at(1);
            return Ok(vec![EnvVar {
                key: key[0].to_string(),
                val: values.join(" "),
                delim,
            }]);
        }

        // Otherwise, we assume all tokens are in the form KEY=VALUE
        let mut env_vars: Vec<EnvVar> = vec![];
        let mut i = 0;
        while i < tokens.len() {
            let token = tokens.get(i).expect("Within length bounded loop");
            if !token.contains('=') {
                return Err(DecodeError::IncompleteInstruction);
            }
            let mut assignment = token.splitn(2, '=');
            let key = assignment.next().unwrap().to_string();
            let val = assignment
                .next()
                .ok_or(DecodeError::IncompleteInstruction)?
                .to_string();
            env_vars.push(EnvVar {
                key,
                val,
                delim: delim.clone(),
            });
            i += 1;
        }
        return Ok(env_vars);
    }

    pub fn set_arguments(&mut self, given_arguments: Vec<u8>) -> Result<(), DecodeError> {
        match self {
            Self::Entrypoint { mode, tokens } | Self::Cmd { mode, tokens } => {
                let mode = mode.as_ref().unwrap();
                if mode.is_exec() {
                    // docker exec commands are given in the form of: ["exec_cmd", "arg1", "arg2"]
                    // so to isolate the individual tokens we need to:
                    // - remove the first and last characters ('[', ']')
                    // - split on "," to get individual terms
                    // - trim each term and remove first and last ('"', '"')
                    let terms = &given_arguments[1..given_arguments.len() - 1]; // remove square brackets
                    let parsed_tokens: Vec<String> = terms
                        .split(|byte| &[*byte] == b",")
                        .filter_map(|token_slice| std::str::from_utf8(token_slice).ok())
                        .map(|token| {
                            let trimmed_token = token.trim();
                            let token_without_leading_quote =
                                trimmed_token.strip_prefix('"').unwrap_or(trimmed_token);
                            token_without_leading_quote
                                .strip_suffix('"')
                                .unwrap_or(token_without_leading_quote)
                                .to_string()
                        })
                        .collect();
                    *tokens = parsed_tokens;
                } else {
                    // docker shell commands are given in the form of: exec_cmd arg1 arg2
                    // so we need to split on space and convert to strings
                    *tokens = given_arguments
                        .as_slice()
                        .split(|byte| &[*byte] == b" ")
                        .filter_map(|token_slice| std::str::from_utf8(token_slice).ok())
                        .map(|token_str| token_str.to_string())
                        .collect();
                }
            }
            Self::Add {
                source_url,
                destination_path,
            } => {
                let parsed_args = given_arguments
                    .as_slice()
                    .split(|byte| &[*byte] == b" ")
                    .filter_map(|token| std::str::from_utf8(token).ok())
                    .filter(|parsed_str| !parsed_str.is_empty())
                    .collect::<Vec<&str>>();
                *source_url = parsed_args
                    .first()
                    .ok_or_else(|| DecodeError::IncompleteInstruction)?
                    .to_string();
                *destination_path = parsed_args
                    .get(1)
                    .ok_or_else(|| DecodeError::IncompleteInstruction)?
                    .to_string();
            }
            Self::Expose { port } => {
                let port_str = std::str::from_utf8(&given_arguments)?;
                let parsed_port = port_str.parse().map_err(DecodeError::InvalidExposedPort)?;
                *port = Some(parsed_port);
            }
            Self::Env { vars } => {
                let vars_str = std::str::from_utf8(&given_arguments)?;
                *vars = Self::parse_env_directive(vars_str.into())?;
            }
            Self::Other { arguments, .. }
            | Self::Comment(arguments)
            | Self::Run(arguments)
            | Self::From { arguments, .. }
            | Self::User(arguments) => *arguments = Bytes::from(given_arguments),
        };
        Ok(())
    }

    fn arguments(&self) -> Option<String> {
        let formatted_args = match self {
            Self::Add {
                source_url,
                destination_path,
            } => format!("{source_url} {destination_path}"),
            Self::Env { vars } => vars
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
                .join(" "),
            Self::Comment(bytes)
            | Self::Run(bytes)
            | Self::User(bytes)
            | Self::From {
                arguments: bytes, ..
            }
            | Self::Other {
                arguments: bytes, ..
            } => std::str::from_utf8(bytes.as_ref())
                .unwrap_or("[Invalid utf8 arguments]")
                .to_string(),
            Self::Entrypoint { mode, tokens } | Self::Cmd { mode, tokens } => {
                if mode.as_ref().map(|mode| mode.is_exec()).unwrap_or(false) {
                    // Recreate an exec mode command — wrap tokens in quotes, and join with ", "
                    let exec_args = tokens.iter().map(|token| format!("\"{}\"", token));
                    format!("[{}]", join(exec_args, ", "))
                } else {
                    join(tokens.as_slice(), " ")
                }
            }
            Self::Expose { port } => {
                return port.as_ref().map(|port| port.to_string());
            }
        };
        Some(formatted_args)
    }

    pub fn tokens(&self) -> Option<&[String]> {
        match self {
            Self::Entrypoint { tokens, .. } | Self::Cmd { tokens, .. } => Some(tokens.as_slice()),
            _ => None,
        }
    }

    pub fn new_entrypoint<T: Into<Vec<String>>>(mode: Mode, tokens: T) -> Self {
        Self::Entrypoint {
            mode: Some(mode),
            tokens: tokens.into(),
        }
    }

    #[allow(dead_code)]
    pub fn new_cmd<T: Into<Vec<String>>>(mode: Mode, tokens: T) -> Self {
        Self::Cmd {
            mode: Some(mode),
            tokens: tokens.into(),
        }
    }

    pub fn new_run<B: Into<Bytes>>(arguments: B) -> Self {
        Self::Run(arguments.into())
    }

    pub fn new_from(key: String) -> Self {
        Self::From {
            arguments: key.clone().into(),
        }
    }

    pub fn new_copy(key: String) -> Self {
        Self::Other {
            directive: "COPY".into(),
            arguments: key.clone().into(),
        }
    }

    pub fn new_add<S: Into<String>>(source_url: S, destination_path: S) -> Self {
        Self::Add {
            source_url: source_url.into(),
            destination_path: destination_path.into(),
        }
    }

    pub fn new_user<S: Into<Bytes>>(user: S) -> Self {
        Self::User(user.into())
    }

    pub fn new_env(vars: Vec<EnvVar>) -> Self {
        Self::Env { vars }
    }
}

impl std::fmt::Display for Directive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let prefix = match self {
            Self::Add { .. } => "ADD",
            Self::Comment(_) => "#",
            Self::Entrypoint { .. } => "ENTRYPOINT",
            Self::Cmd { .. } => "CMD",
            Self::Expose { .. } => "EXPOSE",
            Self::Run(_) => "RUN",
            Self::User(_) => "USER",
            Self::Env { .. } => "ENV",
            Self::Other { directive, .. } => directive.as_str(),
            Self::From { .. } => "FROM",
        };
        write!(
            f,
            "{} {}",
            prefix,
            match self.arguments() {
                Some(str) => str,
                _ => "".to_string(),
            }
        )
    }
}

impl TryFrom<&[u8]> for Directive {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let directive_str = std::str::from_utf8(value)?;

        if directive_str.starts_with('#') {
            return Ok(Self::Comment(Bytes::new()));
        }

        let directive = match directive_str.to_ascii_uppercase().as_str() {
            "ENTRYPOINT" => Self::Entrypoint {
                mode: None,
                tokens: Vec::new(),
            },
            "CMD" => Self::Cmd {
                mode: None,
                tokens: Vec::new(),
            },
            "EXPOSE" => Self::Expose { port: None },
            "RUN" => Self::Run(Bytes::new()),
            "USER" => Self::User(Bytes::new()),
            "ENV" => Self::Env { vars: Vec::new() },
            "FROM" => Self::From {
                arguments: Bytes::new(),
            },
            _ => Self::Other {
                directive: directive_str.to_string(),
                arguments: Bytes::new(),
            },
        };

        Ok(directive)
    }
}

#[derive(Clone)]
enum NewLineBehaviour {
    Escaped,
    IgnoreLine, // handle embedded comments
    Observe,
}

impl NewLineBehaviour {
    pub fn is_escaped(&self) -> bool {
        matches!(self, Self::Escaped)
    }

    pub fn is_observe(&self) -> bool {
        matches!(self, Self::Observe)
    }
}

#[derive(Clone, Debug, PartialEq)]
enum StringToken {
    SingleQuote,
    DoubleQuote,
}

impl TryFrom<u8> for StringToken {
    type Error = DecodeError;

    fn try_from(token: u8) -> Result<Self, Self::Error> {
        let matched_token = match token {
            b'\'' => StringToken::SingleQuote,
            b'"' => StringToken::DoubleQuote,
            _ => return Err(DecodeError::UnexpectedToken),
        };
        Ok(matched_token)
    }
}

// tiny stack which is used to track if we are inside/outside of a string
// which helps with incorrectly treating # in strings as a comment
#[derive(Clone)]
struct StringStack {
    inner: Vec<StringToken>,
}

impl StringStack {
    fn new() -> Self {
        Self { inner: Vec::new() }
    }

    fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    fn peek_top(&self) -> Option<&StringToken> {
        self.inner.iter().last()
    }

    fn pop(&mut self) -> Option<StringToken> {
        self.inner.pop()
    }

    fn push(&mut self, token: StringToken) {
        self.inner.push(token);
    }
}

impl std::fmt::Display for StringStack {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

// States for the Dockerfile decoder's internal state management
#[derive(Clone)]
enum DecoderState {
    Directive(BytesMut),
    DirectiveArguments {
        directive: Directive,
        arguments: Option<BytesMut>,
        new_line_behaviour: NewLineBehaviour,
        string_stack: StringStack,
    },
    Comment(BytesMut),
    Whitespace,
}

// Helper function to clear out any lingering state in the Decoder on eof
// Mainly used to prevent failed parsing when the final directive in a fail doesn't have a newline
impl std::convert::TryInto<Option<Directive>> for DecoderState {
    type Error = DecodeError;

    fn try_into(self) -> Result<Option<Directive>, Self::Error> {
        match self {
            Self::Comment(content) => Ok(Some(Directive::Comment(Bytes::from(content)))),
            Self::DirectiveArguments {
                mut directive,
                arguments,
                ..
            } => {
                let arguments = arguments.ok_or(DecodeError::IncompleteInstruction)?;
                directive.set_arguments(arguments.to_vec())?;
                Ok(Some(directive))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("An error occured while decoding the dockerfile - {0:?}")]
    IoError(#[from] tokio::io::Error),
    #[error("Unexpected token found in the dockerfile")]
    UnexpectedToken,
    #[error("Encountered invalid utf8 in the dockerfile - {0:?}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("No CMD or Entrypoint directives found")]
    NoEntrypoint,
    #[error("Incomplete instruction found")]
    IncompleteInstruction,
    #[error("Failed to parse the exposed port")]
    InvalidExposedPort(ParseIntError),
}

impl std::convert::TryFrom<u8> for DecoderState {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value.is_ascii_whitespace() {
            Ok(Self::Whitespace)
        } else if value.is_ascii_alphabetic() {
            let mut bytes = BytesMut::with_capacity(1);
            bytes.put_u8(value);
            Ok(Self::Directive(bytes))
        } else if value == b'#' {
            Ok(Self::Comment(BytesMut::new()))
        } else {
            Err(DecodeError::UnexpectedToken)
        }
    }
}

pub struct DockerfileDecoder {
    current_state: Option<DecoderState>,
}

#[allow(dead_code)]
impl std::default::Default for DockerfileDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerfileDecoder {
    pub fn new() -> Self {
        Self {
            current_state: None,
        }
    }

    pub fn flush(&mut self) -> Result<Option<Directive>, DecodeError> {
        if self.current_state.is_none() {
            Ok(None)
        } else {
            self.current_state.take().unwrap().try_into()
        }
    }

    fn read_u8(&mut self, src: &mut BytesMut) -> Option<u8> {
        if src.has_remaining() {
            Some(src.get_u8())
        } else {
            None
        }
    }

    fn derive_new_line_state(
        &mut self,
        first_byte: u8,
    ) -> Result<Option<DecoderState>, DecodeError> {
        let initial_state = if first_byte.is_ascii_whitespace() {
            DecoderState::Whitespace
        } else if first_byte.is_ascii_alphabetic() {
            let mut bytes = BytesMut::with_capacity(1);
            bytes.put_u8(first_byte);
            DecoderState::Directive(bytes)
        } else if first_byte == b'#' {
            DecoderState::Comment(BytesMut::with_capacity(1))
        } else {
            return Err(DecodeError::UnexpectedToken);
        };

        Ok(Some(initial_state))
    }

    fn decode_whitespace(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<DecoderState>, DecodeError> {
        // Read until end of whitespace
        let new_char = loop {
            match self.read_u8(src) {
                Some(byte) if byte.is_ascii_whitespace() => continue,
                Some(byte) => break byte,
                None => return Ok(None),
            }
        };

        self.derive_new_line_state(new_char)
    }

    fn decode_comment(
        &mut self,
        src: &mut BytesMut,
        content: &mut BytesMut,
    ) -> Result<Option<Directive>, DecodeError> {
        loop {
            match self.read_u8(src) {
                Some(b'\n') => {
                    let comment_bytes = Bytes::from(content.to_vec());
                    return Ok(Some(Directive::Comment(comment_bytes)));
                }
                Some(next_byte) => {
                    content.put_u8(next_byte);
                }
                None => {
                    return Ok(None);
                }
            };
        }
    }

    fn decode_directive(
        &mut self,
        src: &mut BytesMut,
        directive: &mut BytesMut,
    ) -> Result<Option<DecoderState>, DecodeError> {
        loop {
            match self.read_u8(src) {
                Some(b' ') => {
                    return Ok(Some(DecoderState::DirectiveArguments {
                        directive: Directive::try_from(directive.as_ref())?,
                        arguments: None,
                        new_line_behaviour: NewLineBehaviour::Observe,
                        string_stack: StringStack::new(),
                    }));
                }
                Some(byte) if byte.is_ascii() => {
                    directive.put_u8(byte);
                    continue;
                }
                Some(_) => return Err(DecodeError::UnexpectedToken),
                None => return Ok(None),
            }
        }
    }

    fn decode_directive_arguments(
        &mut self,
        src: &mut BytesMut,
        directive: &mut Directive,
        arguments: &mut Option<BytesMut>,
        new_line_behaviour: &mut NewLineBehaviour,
        string_stack: &mut StringStack,
    ) -> Result<Option<Directive>, DecodeError> {
        // read until new line, not preceded by '\'
        loop {
            match self.read_u8(src) {
                // if we see a newline character or backslash as the first character for a directives argument
                // return an error
                Some(next_byte)
                    if (next_byte == b'\n' || next_byte == b'\\') && arguments.is_none() =>
                {
                    return Err(DecodeError::UnexpectedToken)
                }
                // newline is either escaped or we are reading an embedded comment
                Some(next_byte) if next_byte == b'\n' && !new_line_behaviour.is_observe() => {
                    if arguments.is_none() {
                        *arguments = Some(BytesMut::new());
                    }
                    let argument_mut = arguments.as_mut().unwrap();
                    argument_mut.put_u8(next_byte);
                }
                // new line signifies end of directive if unescaped
                Some(b'\n') => {
                    // safety: first arm will be matched if next_byte is a newline and arguments is None
                    let content = arguments.as_ref().unwrap().to_vec();
                    directive.set_arguments(content)?;
                    return Ok(Some(directive.clone()));
                }
                // if a newline character is next, escape it, if already escaped then observe (\\)
                Some(next_byte) if next_byte == b'\\' => {
                    if new_line_behaviour.is_escaped() {
                        *new_line_behaviour = NewLineBehaviour::Observe;
                    } else if new_line_behaviour.is_observe() {
                        *new_line_behaviour = NewLineBehaviour::Escaped;
                    }
                    arguments.as_mut().unwrap().put_u8(next_byte);
                }
                // ignore leading space on directive arguments
                Some(next_byte) if next_byte == b' ' && arguments.is_none() => continue,
                Some(next_byte) if next_byte == b'#' => {
                    // check if # signifies a comment or is embedded within an instruction
                    if string_stack.is_empty() {
                        let is_newline_comment = arguments
                            .as_ref()
                            .map(|bytes| bytes.ends_with(b"\\\n"))
                            .unwrap_or(false);
                        if is_newline_comment {
                            // ignore next newline — will terminate comment, not directive args
                            *new_line_behaviour = NewLineBehaviour::IgnoreLine;
                        } else {
                            *new_line_behaviour = NewLineBehaviour::Observe;
                        }
                    }
                    if arguments.is_none() {
                        *arguments = Some(BytesMut::new());
                    }
                    let argument_mut = arguments.as_mut().unwrap();
                    argument_mut.put_u8(next_byte);
                }
                // nothing special about this byte, so add to arguments buffer
                Some(next_byte) => {
                    if arguments.is_none() {
                        // first char for CMD & EXEC determines the mode (shell vs exec)
                        if directive.is_cmd() || directive.is_entrypoint() {
                            directive.set_mode(Mode::from(next_byte));
                        }
                        *arguments = Some(BytesMut::new());
                    }
                    let argument_mut = arguments.as_mut().unwrap();
                    argument_mut.put_u8(next_byte);

                    // only update new line behaviour when escaped (i.e. cancel \ if followed by non-newline char)
                    // if new line behaviour is set to ignore line, then we are in an embedded comment, new line remains escaped
                    if new_line_behaviour.is_escaped() {
                        *new_line_behaviour = NewLineBehaviour::Observe;
                    }

                    // if this byte is a string character, check if stack can be popped, else push
                    if next_byte == b'\'' || next_byte == b'"' {
                        let token = StringToken::try_from(next_byte).unwrap();
                        if string_stack.peek_top() == Some(&token) {
                            string_stack.pop();
                        } else {
                            string_stack.push(token);
                        }
                    }
                }
                None => return Ok(None),
            }
        }
    }

    pub async fn decode_dockerfile_from_src<R: AsyncRead + std::marker::Unpin>(
        dockerfile_src: R,
    ) -> Result<Vec<Directive>, super::error::DockerError> {
        let mut dockerfile_reader = FramedRead::new(dockerfile_src, Self::new());

        let mut directives = Vec::new();

        while let Some(directive) = dockerfile_reader.next().await.transpose()? {
            directives.push(directive);
        }

        Ok(directives)
    }
}

impl Decoder for DockerfileDecoder {
    type Item = Directive;
    type Error = super::error::DockerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut decode_state = if self.current_state.is_none() {
            let first_byte = match self.read_u8(src) {
                Some(byte) => byte,
                None => return Ok(None),
            };
            match self.derive_new_line_state(first_byte)? {
                Some(initial_state) => initial_state,
                None => return Ok(None),
            }
        } else {
            self.current_state.take().unwrap()
        };

        loop {
            let next_state = match decode_state {
                DecoderState::Whitespace => self.decode_whitespace(src)?,
                DecoderState::Comment(mut content) => {
                    return match self.decode_comment(src, &mut content)? {
                        Some(directive) => Ok(Some(directive)),
                        None => {
                            self.current_state = Some(DecoderState::Comment(content));
                            Ok(None)
                        }
                    };
                }
                DecoderState::Directive(mut directive) => {
                    let next_state = self.decode_directive(src, &mut directive)?;
                    if next_state.is_none() {
                        self.current_state = Some(DecoderState::Directive(directive));
                    }
                    next_state
                }
                DecoderState::DirectiveArguments {
                    mut directive,
                    mut arguments,
                    mut new_line_behaviour,
                    mut string_stack,
                } => {
                    return match self.decode_directive_arguments(
                        src,
                        &mut directive,
                        &mut arguments,
                        &mut new_line_behaviour,
                        &mut string_stack,
                    )? {
                        Some(instruction) => Ok(Some(instruction)),
                        None => {
                            self.current_state = Some(DecoderState::DirectiveArguments {
                                directive,
                                arguments,
                                new_line_behaviour,
                                string_stack,
                            });
                            Ok(None)
                        }
                    };
                }
            };

            match next_state {
                Some(next_state) => {
                    decode_state = next_state;
                }
                None => return Ok(None),
            }
        }
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(buf)? {
            Some(directive) => Ok(Some(directive)),
            None => Ok(self.flush()?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_directive_has_been_parsed<E: std::error::Error>(
        parsed_directive: Result<Option<Directive>, E>,
    ) -> Directive {
        assert_eq!(parsed_directive.is_ok(), true);
        let directive = parsed_directive.unwrap();
        assert_eq!(directive.is_some(), true);
        directive.unwrap()
    }

    fn assert_directive_has_not_been_parsed<E: std::error::Error>(
        parsed_directive: Result<Option<Directive>, E>,
    ) {
        assert_eq!(parsed_directive.is_ok(), true);
        let directive = parsed_directive.unwrap();
        assert_eq!(directive.is_none(), true);
    }

    #[test]
    fn test_decoding_of_directive_with_comments() {
        let mut decoder = DockerfileDecoder::new();
        let test_directive = "ENTRYPOINT echo 'Test' # emits Test";
        let directive_with_new_line = format!("{}\n", test_directive);
        let mut dockerfile_content = BytesMut::from(directive_with_new_line.as_str());
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        let directive = assert_directive_has_been_parsed(emitted_directive);
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(directive.to_string(), String::from(test_directive));
    }

    #[test]
    fn test_flush_on_file_without_final_newline() {
        let mut decoder = DockerfileDecoder::new();
        let test_directive = "ENTRYPOINT echo 'Test' # emits Test";
        let mut dockerfile_content = BytesMut::from(test_directive);
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_not_been_parsed(emitted_directive);
        let flushed_directive = decoder.flush();
        let directive = assert_directive_has_been_parsed(flushed_directive);
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(directive.to_string(), String::from(test_directive));
    }

    #[test]
    fn test_flush_on_incomplete_state() {
        let mut decoder = DockerfileDecoder::new();
        let test_directive = "ENTRYPOINT ";
        let mut dockerfile_content = BytesMut::from(test_directive);
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_not_been_parsed(emitted_directive);
        let flushed_state = decoder.flush();
        assert_eq!(flushed_state.is_err(), true);
    }

    #[test]
    fn test_multiline_directive_with_embedded_comments() {
        let mut decoder = DockerfileDecoder::new();
        // using entrypoint for apk updates doesn't really make sense, purely for testing
        let test_dockerfile = r#"
FROM node:16-alpine3.14
ENTRYPOINT apk update && apk add python3 glib make g++ gcc libc-dev &&\
# clean apk cache
    rm -rf /var/cache/apk/* # testing"#;
        let mut dockerfile_content = BytesMut::from(test_dockerfile);
        let from_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_been_parsed(from_directive);
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_not_been_parsed(emitted_directive);
        let flushed_state = decoder.flush();
        let directive = assert_directive_has_been_parsed(flushed_state);
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(
            directive.to_string(),
            String::from(
                r#"ENTRYPOINT apk update && apk add python3 glib make g++ gcc libc-dev &&\
# clean apk cache
    rm -rf /var/cache/apk/* # testing"#
            )
        );
    }

    #[test]
    fn test_parsing_of_command_with_hashbang() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"RUN /bin/sh -c "echo -e '"'#!/bin/sh\necho "Hello, World!"'"' > /etc/service/hello_world/run""#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(), test_dockerfile.to_string());
    }

    #[test]
    fn test_parsing_of_command_with_uneven_apostrophes() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile =
            r#"RUN /bin/sh -c "echo -e '"'#!/bin/sh\necho "'"\n'"' > /etc/service/apostrophe/run""#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(), test_dockerfile.to_string());
    }

    #[test]
    fn test_parsing_of_entrypoint_exec_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENTRYPOINT ["node", "server.js"]"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(), test_dockerfile.to_string());
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(directive.mode().unwrap(), &Mode::Exec);
    }

    #[test]
    fn test_parsing_of_entrypoint_shell_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENTRYPOINT node server.js"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(), test_dockerfile.to_string());
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(directive.mode().unwrap(), &Mode::Shell);
    }

    #[test]
    fn test_parsing_of_cmd_exec_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"CMD ["node", "server.js"]"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(), test_dockerfile.to_string());
        assert_eq!(directive.is_cmd(), true);
        assert_eq!(directive.mode().unwrap(), &Mode::Exec);
    }

    #[test]
    fn test_parsing_of_cmd_shell_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"CMD node server.js"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(), test_dockerfile.to_string());
        assert_eq!(directive.is_cmd(), true);
        assert_eq!(directive.mode().unwrap(), &Mode::Shell);
    }

    #[test]
    fn test_parsing_of_expose_directives() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"EXPOSE 80"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let expose_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(expose_directive);
        assert_eq!(directive.to_string(), test_dockerfile.to_string());
        assert_eq!(directive.is_expose(), true);
        assert!(matches!(directive, Directive::Expose { port: Some(80) }));
    }

    #[test]
    fn test_parsing_of_single_env_directives() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENV Hello=World"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let env_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(env_directive);

        assert_eq!(directive.to_string(), test_dockerfile.to_string());
        assert_eq!(directive.is_env(), true);
    }

    #[test]
    fn test_parsing_of_multiple_env_directives() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENV Hello=World World=Hello"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let env_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(env_directive);

        assert_eq!(directive.to_string(), test_dockerfile.to_string());
        assert_eq!(directive.is_env(), true);
    }

    #[test]
    fn test_parsing_of_non_standard_env_directives() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENV Hello World"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let env_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(env_directive);

        assert_eq!(directive.to_string(), "ENV Hello World".to_string());
        assert_eq!(directive.is_env(), true);
    }

    #[test]
    fn test_parsing_env_directive_containing_equals() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENV FOO=BAR=true"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let env_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(env_directive);

        assert_eq!(directive.to_string(), r#"ENV FOO=BAR=true"#.to_string());
        assert_eq!(directive.is_env(), true);
    }

    #[test]
    fn test_parsing_env_directive_with_uneven_equals_assignments() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENV FOO=BAR=true BAR=BAZ"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let env_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(env_directive);

        assert_eq!(
            directive.to_string(),
            r#"ENV FOO=BAR=true BAR=BAZ"#.to_string()
        );
        assert_eq!(directive.is_env(), true);
    }

    #[tokio::test]
    async fn test_decode_from_async_src() {
        let test_dockerfile = b"EXPOSE 80\nENTRYPOINT [\"echo\",\"yo\"]";
        let mut mock_builder = tokio_test::io::Builder::new();
        mock_builder.read(test_dockerfile);
        let mock = mock_builder.build();
        let decoded_file = DockerfileDecoder::decode_dockerfile_from_src(mock).await;
        assert!(decoded_file.is_ok());
        let decoded_file = decoded_file.unwrap();
        assert_eq!(decoded_file.len(), 2);
        let expose_directive = decoded_file.get(0).unwrap();
        assert!(matches!(
            expose_directive,
            Directive::Expose { port: Some(80) }
        ));
        let entrypoint_directive = decoded_file.get(1).unwrap();
        assert!(entrypoint_directive.is_entrypoint());
        if let Directive::Entrypoint { mode, tokens } = entrypoint_directive {
            assert_eq!(*mode, Some(Mode::Exec));
            assert_eq!(tokens.len(), 2);
            assert_eq!(tokens.as_slice(), &["echo".to_string(), "yo".to_string()]);
        }
    }

    #[test]
    fn test_constructor_for_run_commands() {
        let run_directive = Directive::new_run("echo 'Test'".to_string());
        assert_eq!(run_directive.is_run(), true);
        assert_eq!(run_directive.to_string(), String::from("RUN echo 'Test'"))
    }

    #[test]
    fn test_constructor_for_entrypoint_commands() {
        let entrypoint_directive =
            Directive::new_entrypoint(Mode::Shell, vec!["echo 'Test'".to_string()]);
        assert_eq!(entrypoint_directive.is_entrypoint(), true);
        assert_eq!(entrypoint_directive.mode().unwrap(), &Mode::Shell);
        assert_eq!(
            entrypoint_directive.to_string(),
            String::from("ENTRYPOINT echo 'Test'")
        )
    }

    #[test]
    fn test_constructor_for_cmd_commands() {
        let entrypoint_directive = Directive::new_cmd(Mode::Shell, vec!["echo 'Test'".to_string()]);
        assert_eq!(entrypoint_directive.is_cmd(), true);
        assert_eq!(entrypoint_directive.mode().unwrap(), &Mode::Shell);
        assert_eq!(
            entrypoint_directive.to_string(),
            String::from("CMD echo 'Test'")
        )
    }

    #[test]
    fn test_constructor_for_env_commands_with_eq_delim() {
        let env_directive = Directive::new_env(vec![EnvVar {
            key: "Hello".to_string(),
            val: "World".to_string(),
            delim: Delimiter::Eq,
        }]);

        assert_eq!(env_directive.is_env(), true);
        assert_eq!(env_directive.to_string(), "ENV Hello=World".to_string());
    }

    #[test]
    fn test_constructor_for_env_commands_with_none_delim() {
        let env_directive = Directive::new_env(vec![EnvVar {
            key: "Hello".to_string(),
            val: "World".to_string(),
            delim: Delimiter::None,
        }]);

        assert_eq!(env_directive.is_env(), true);
        assert_eq!(env_directive.to_string(), "ENV Hello World".to_string());
    }

    #[test]
    fn test_multiple_var_env_directive() {
        let env_directive = Directive::new_env(vec![
            EnvVar {
                key: "Hello".to_string(),
                val: "World".to_string(),
                delim: Delimiter::Eq,
            },
            EnvVar {
                key: "World".to_string(),
                val: "Hello".to_string(),
                delim: Delimiter::Eq,
            },
        ]);

        assert_eq!(env_directive.to_string(), "ENV Hello=World World=Hello");
    }
}
