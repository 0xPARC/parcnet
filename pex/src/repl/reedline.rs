use nu_ansi_term::{Color, Style as AnsiStyle};
use reedline::{Completer, Highlighter, Span, StyledText, Suggestion, ValidationResult, Validator};

pub struct LispHighlighter {
    commands: Vec<String>,
    matching_bracket_style: AnsiStyle,
    keyword_style: AnsiStyle,
    normal_bracket_style: AnsiStyle,
}

impl LispHighlighter {
    pub fn new(commands: Vec<String>) -> Self {
        Self {
            commands,
            matching_bracket_style: AnsiStyle::new().bold().fg(Color::Green),
            keyword_style: AnsiStyle::new().fg(Color::Purple),
            normal_bracket_style: AnsiStyle::new().fg(Color::Cyan),
        }
    }

    fn find_matching_bracket(&self, line: &str, cursor: usize) -> Option<usize> {
        let chars: Vec<char> = line.chars().collect();

        // If cursor is not on a bracket, return None
        if cursor >= chars.len() || (chars[cursor] != '[' && chars[cursor] != ']') {
            return None;
        }

        let (is_opening, _matching_char, _direction, limit) = if chars[cursor] == '[' {
            (true, ']', 1, chars.len())
        } else {
            (false, '[', -1, 0)
        };

        let mut count = 1;
        let mut pos = cursor;

        while count > 0 {
            pos = if is_opening {
                pos + 1
            } else {
                pos.checked_sub(1)?
            };

            if (is_opening && pos >= limit) || (!is_opening && pos <= limit) {
                return None;
            }

            match chars[pos] {
                '[' if !is_opening => count -= 1,
                ']' if is_opening => count -= 1,
                '[' if is_opening => count += 1,
                ']' if !is_opening => count += 1,
                _ => {}
            }
        }

        Some(pos)
    }
}
impl Highlighter for LispHighlighter {
    fn highlight(&self, line: &str, cursor: usize) -> StyledText {
        let mut styled = StyledText::new();
        let mut in_word = false;
        let mut word_start = 0;

        // Find matching bracket if cursor is on a bracket
        let matching_pos = self.find_matching_bracket(line, cursor);

        for (i, c) in line.chars().enumerate() {
            match c {
                '[' | ']' => {
                    if in_word {
                        let word = &line[word_start..i];
                        if self.commands.contains(&word.to_string()) {
                            styled.push((self.keyword_style, word.to_string()));
                        } else {
                            styled.push((AnsiStyle::new(), word.to_string()));
                        }
                        in_word = false;
                    }

                    // Use matching style if this is either the cursor position or its matching bracket
                    if Some(i) == matching_pos || i == cursor {
                        styled.push((self.matching_bracket_style, line[i..i + 1].to_string()));
                    } else {
                        styled.push((self.normal_bracket_style, line[i..i + 1].to_string()));
                    }
                }
                ' ' | '\t' | '\n' => {
                    if in_word {
                        let word = &line[word_start..i];
                        if self.commands.contains(&word.to_string()) {
                            styled.push((self.keyword_style, word.to_string()));
                        } else {
                            styled.push((AnsiStyle::new(), word.to_string()));
                        }
                        in_word = false;
                    }
                    styled.push((AnsiStyle::new(), line[i..i + 1].to_string()));
                }
                _ => {
                    if !in_word {
                        word_start = i;
                        in_word = true;
                    }
                }
            }
        }

        // Handle the last word if exists
        if in_word {
            let word = &line[word_start..];
            if self.commands.contains(&word.to_string()) {
                styled.push((self.keyword_style, word.to_string()));
            } else {
                styled.push((AnsiStyle::new(), word.to_string()));
            }
        }

        styled
    }
}
pub struct LispValidator;

impl Validator for LispValidator {
    fn validate(&self, line: &str) -> ValidationResult {
        let mut balance = 0;
        for c in line.chars() {
            match c {
                '[' => balance += 1,
                ']' => balance -= 1,
                _ => (),
            }
        }

        if balance > 0 {
            ValidationResult::Incomplete
        } else {
            ValidationResult::Complete
        }
    }
}

pub struct LispCompleter {
    commands: Vec<String>,
}

impl LispCompleter {
    pub fn new(commands: Vec<String>) -> Self {
        Self { commands }
    }

    fn get_word_at_cursor(&self, line: &str, pos: usize) -> (usize, String) {
        let mut start = pos;
        while start > 0 && !line[..start].ends_with(['[', ' ', '\t', '\n']) {
            start -= 1;
        }
        (start, line[start..pos].trim_start().to_string())
    }
}

impl Completer for LispCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let (start, current_word) = self.get_word_at_cursor(line, pos);
        if current_word.is_empty() {
            return vec![];
        }

        self.commands
            .iter()
            .filter(|cmd| cmd.starts_with(&current_word))
            .map(|cmd| Suggestion {
                value: cmd.clone(),
                description: None,
                extra: None,
                span: Span::new(start, pos),
                style: None,
                append_whitespace: true,
            })
            .collect()
    }
}
