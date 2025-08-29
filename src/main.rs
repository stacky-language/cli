use clap::{Parser, Subcommand};
use rustyline::Editor;
use rustyline::Helper;
use rustyline::completion::Completer;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use stacky::Error;
use stacky::Errors;
use stacky::Position;
use stacky::{ErrorKind, Interpreter, Script, Value};
use std::borrow::Cow;
use std::cell::RefCell;
use std::io::{Write, stdin, stdout};
use std::rc::Rc;

#[derive(Parser)]
#[command(name = "stacky", bin_name = "stacky")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// File to run.
    #[arg()]
    file: Option<String>,

    /// Arguments passed to the program when running a file.
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Check (parse/validate) a script file without running")]
    Check {
        /// File to check
        file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Check { file }) => {
            if let Err(errors) = Script::from_file(&file) {
                for e in errors.inner() {
                    println!("{e}");
                }
            }
        }
        None => {
            // No subcommand: if a file was provided, run it; otherwise start REPL
            if let Some(file) = cli.file {
                match run_file(
                    &file,
                    &cli.args.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                ) {
                    Ok(()) => {}
                    Err(errors) => {
                        let mut exit_code = 1;
                        for e in errors.inner() {
                            if let ErrorKind::Exit(code) = &e.kind {
                                exit_code = *code as i32;
                            } else {
                                eprintln!("{e}");
                            }
                        }
                        std::process::exit(exit_code);
                    }
                }
            } else {
                if let Err(e) = repl() {
                    println!("{e}");
                }
            }
        }
    };
}

struct StdOutWrapper {
    inner: std::io::Stdout,
    ended_with_newline: Rc<RefCell<bool>>,
}

impl Write for StdOutWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.ended_with_newline.replace(buf[n - 1] == b'\n');
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn repl() -> Result<(), Error> {
    println!("Whelcome to Stacky {}!", env!("CARGO_PKG_VERSION"));

    let last_ended = Rc::new(RefCell::new(true));
    let writer = StdOutWrapper {
        inner: stdout(),
        ended_with_newline: last_ended.clone(),
    };

    let mut interpreter = Interpreter::new()
        .with_input(stdin().lock())
        .with_output(writer);
    let mut rl = Editor::new().map_err(|e| Error {
        file_name: "main".to_string(),
        kind: ErrorKind::InvalidArgument(format!("Failed to create editor: {}", e)),
        pos: Position::default(),
    })?;

    rl.set_helper(Some(StackyHighlighter {}));

    loop {
        let readline = rl.readline("\x1b[90m>\x1b[0m ");
        match readline {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                rl.add_history_entry(input).ok();

                match Script::from_str(input) {
                    Ok(script) => match interpreter.run(&script, &[]) {
                        Ok(_) => {
                            if !*last_ended.borrow() {
                                println!();
                                last_ended.replace(true);
                            }
                            print_stack(interpreter.stack());
                        }
                        Err(e) => match &e.kind {
                            ErrorKind::Exit(code) => {
                                println!("exit with code: {}", code);
                                std::process::exit(*code as i32);
                            }
                            _ => println!("\x1b[31merror: {}\x1b[0m", e.kind),
                        },
                    },
                    Err(errors) => {
                        for e in errors.inner() {
                            println!("\x1b[31merror: {}\x1b[0m", e.kind);
                        }
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("^C");
                break;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("^D");
                break;
            }
            Err(err) => {
                println!("\x1b[31merror: {:?}\x1b[0m", err);
                break;
            }
        }
    }

    Ok(())
}

struct StackyHighlighter;

impl Highlighter for StackyHighlighter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        let keywords = ["true", "false", "nil"];
        // known type names for syntax highlighting
        let type_names = ["string", "int", "float", "ptr", "bool", "nil"];
        let commands = [
            "nop", "push", "pop", "add", "sub", "mul", "div", "mod", "neg", "dup", "print",
            "println", "read", "goto", "br", "label", "load", "store", "gt", "lt", "ge", "le",
            "eq", "ne", "and", "or", "not", "xor", "shl", "shr", "convert", "rotl", "rotr", "clz",
            "ctz", "min", "max", "abs", "sign", "ceil", "floor", "trunc", "sqrt", "len", "pow",
            "sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh", "tanh", "asinh", "acosh",
            "atanh", "exp", "log", "getenv", "getarg", "malloc", "free", "memset", "memcpy",
            "memcmp", "assert", "error", "exit",
        ];

        if let Some(pos) = line.find(';') {
            let before = &line[..pos];
            let after = &line[pos..];
            let highlighted_before = self.highlight(before, 0);
            return Cow::Owned(format!(
                "{}{}\x1b[38;5;71m{}\x1b[0m",
                highlighted_before, "", after
            ));
        }

        let mut result = String::new();
        let mut chars = line.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == ':'
                && chars
                    .peek()
                    .map_or(false, |c| c.is_alphabetic() || *c == '_')
            {
                // Label
                let mut label = String::new();
                label.push(ch);
                while let Some(&next_ch) = chars.peek() {
                    if next_ch.is_alphanumeric() || next_ch == '_' {
                        label.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                result.push_str(&format!("\x1b[38;5;252m{}\x1b[0m", label));
            } else if ch.is_alphabetic() || ch == '_' {
                let mut word = String::new();
                word.push(ch);
                while let Some(&next_ch) = chars.peek() {
                    if next_ch.is_alphanumeric() || next_ch == '_' {
                        word.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                if type_names.contains(&word.as_str()) {
                    result.push_str(&format!("\x1b[38;2;86;156;214m{}\x1b[0m", word));
                } else if keywords.contains(&word.as_str()) {
                    result.push_str(&format!("\x1b[38;5;74m{}\x1b[0m", word));
                } else if commands.contains(&word.as_str()) {
                    result.push_str(&format!("\x1b[38;5;187m{}\x1b[0m", word));
                } else {
                    result.push_str(&word);
                }
            } else if ch == '0'
                && chars
                    .peek()
                    .map_or(false, |&c| c == 'x' || c == 'X' || c == 'b' || c == 'B')
            {
                // Hexadecimal or binary literals
                let mut num = String::new();
                num.push(ch);
                let prefix = chars.next().unwrap();
                num.push(prefix);

                let is_hex = prefix == 'x' || prefix == 'X';
                while let Some(&next_ch) = chars.peek() {
                    if (is_hex && (next_ch.is_ascii_hexdigit()))
                        || (!is_hex && (next_ch == '0' || next_ch == '1'))
                    {
                        num.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                result.push_str(&format!("\x1b[38;5;151m{}\x1b[0m", num));
            } else if ch.is_digit(10) || ch == '.' || ch == '-' {
                // Regular numbers (including scientific notation)
                let mut num = String::new();
                num.push(ch);
                let mut has_dot = ch == '.';
                let mut has_e = false;

                while let Some(&next_ch) = chars.peek() {
                    if next_ch.is_digit(10) {
                        num.push(chars.next().unwrap());
                    } else if next_ch == '.' && !has_dot && !has_e {
                        has_dot = true;
                        num.push(chars.next().unwrap());
                    } else if (next_ch == 'e' || next_ch == 'E') && !has_e && num.len() > 0 {
                        has_e = true;
                        num.push(chars.next().unwrap());
                        // Check for optional +/- after e/E
                        if chars.peek().map_or(false, |&c| c == '+' || c == '-') {
                            num.push(chars.next().unwrap());
                        }
                    } else {
                        break;
                    }
                }
                result.push_str(&format!("\x1b[38;5;151m{}\x1b[0m", num));
            } else if ch == '"' {
                let mut string = String::new();
                string.push(ch);
                while let Some(next_ch) = chars.next() {
                    string.push(next_ch);
                    if next_ch == '"' {
                        break;
                    }
                }
                result.push_str(&format!("\x1b[38;5;180m{}\x1b[0m", string));
            } else {
                result.push(ch);
            }
        }

        Cow::Owned(result)
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        true
    }
}

impl Helper for StackyHighlighter {}

impl Validator for StackyHighlighter {
    fn validate(
        &self,
        _ctx: &mut rustyline::validate::ValidationContext,
    ) -> rustyline::Result<rustyline::validate::ValidationResult> {
        Ok(rustyline::validate::ValidationResult::Valid(None))
    }
}

impl Hinter for StackyHighlighter {
    type Hint = String;
}

impl Completer for StackyHighlighter {
    type Candidate = String;
}

fn print_stack(stack: &[Value]) {
    if stack.is_empty() {
        println!("\x1b[90m[]\x1b[0m");
    } else {
        print!("\x1b[90m[\x1b[0m");
        for (i, val) in stack.iter().enumerate() {
            if i > 0 {
                print!("\x1b[90m, \x1b[0m");
            }
            match val {
                Value::Nil => print!("\x1b[38;5;74mnil\x1b[0m"),
                Value::Int(i) => print!("\x1b[38;5;151m{}\x1b[0m", i),
                Value::Float(f) => {
                    if (f - f.round()).abs() < f64::EPSILON {
                        print!("\x1b[38;5;151m{:.1}\x1b[0m", f);
                    } else {
                        print!("\x1b[38;5;151m{}\x1b[0m", f);
                    }
                }
                Value::Bool(b) => print!("\x1b[38;5;74m{}\x1b[0m", b),
                Value::String(s) => print!("\x1b[38;5;180m\"{}\"\x1b[0m", s),
            }
        }
        println!("\x1b[90m]\x1b[0m");
    }
}

fn run_file(filename: &str, args: &[&str]) -> Result<(), Errors> {
    let script = Script::from_file(&filename)?;
    let mut interpreter = Interpreter::new().with_stdio();
    interpreter
        .run(&script, args)
        .map_err(|e| Errors::from(e))?;
    Ok(())
}
