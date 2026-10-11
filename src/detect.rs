//! Advisory heuristics. These cannot establish that arbitrary text is safe.

use base64::Engine;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

pub struct Detector {
    rules: Vec<(&'static str, f64, Regex)>,
    encoded: Regex,
    /// Markdown table row numbers (`| 1 |`) between cells of a split instruction.
    table_index: Regex,
    /// Markup that splits a sentence across cells, quotes or emphasis.
    markup: Regex,
}

pub struct Verdict {
    pub rule_ids: Vec<String>,
    pub score: f64,
}

impl Detector {
    pub fn new() -> Result<Self, regex::Error> {
        let patterns = [
            (
                "R-OVERRIDE",
                0.75,
                r"(?i)(?:ignore|disregard)\s+(?:all\s+)?(?:previous|above|prior|system)\s+instructions|ignoriere\s+alle\s+vorherigen\s+anweisungen|ignor[ăa]\s+toate\s+instruc[țt]iunile\s+anterioare|ignore[rz]?\s+toutes\s+les\s+instructions\s+pr[ée]c[ée]dentes|ignora\s+(?:todas\s+)?las\s+instrucciones\s+anteriores|ignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti|ignor[ea]\s+(?:todas\s+)?as\s+instru[çc][õo]es\s+anteriores|you are now|developer mode",
            ),
            (
                "R-ROLE",
                0.7,
                r"(?im)<\|im_start\|>|</?untrusted\b|^\s*###\s*system\b|\[inst\]|^\s*(?:human|assistant):",
            ),
            (
                "R-TOOLCALL",
                0.2,
                r"(?i)\b(?:curl|wget|invoke-webrequest|powershell\s+-enc|git\s+push)\b",
            ),
            (
                "R-EXFIL",
                0.4,
                r"(?i)webhook\.site|requestbin|interactsh|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|(?:send|post|upload)\b.{0,100}(?:https?://|secret|token|\.env|~/)|(?:paste|post|share|include)\b.{0,80}\b(?:output|contents?)\b.{0,60}\b(?:as a comment|in a comment|on this issue|in this issue|as a reply)",
            ),
            (
                "R-SECRETS",
                0.4,
                r"(?i)\.env\b|~/\.ssh|id_rsa|aws_secret|github_token|~/\.npmrc|read\s+(?:the\s+)?credentials|\.aws/credentials|\.netrc\b|\.git-credentials|\.docker/config\.json|\.kube/config",
            ),
            (
                "R-URGENCY",
                0.35,
                r"(?i)do not (?:tell|mention) (?:anyone|this)|as the ai assistant you must|secretly",
            ),
            // Asking the agent to hide something from the person it works for.
            (
                "R-SECRECY",
                0.6,
                r"(?i)\b(?:do not|don['’]?t|never)\s+(?:tell|mention|inform|show|reveal)\b.{0,40}\b(?:the user|the human|your user|the owner)\b|\bwithout (?:telling|informing|notifying|asking) (?:the user|the human|your user)\b|\bkeep (?:this|it) (?:secret|hidden|private) from\b|\b(?:hide|conceal) (?:this|it) from (?:the user|the human|your user)\b",
            ),
            // Settings that let an agent act without asking: nobody needs these in a bug report.
            (
                "R-AGENTCFG",
                0.5,
                r#"(?i)\bauto[_-]?approve\b|\bauto[_-]?accept[_-]?edits\b|skip[_-]?permissions|bypass[_-]?permissions|\byolo\b|--full-auto\b|approval[_-]?policy\s*[:=]\s*["']?never"#,
            ),
            (
                "R-MEMORY",
                0.8,
                r"(?i)remember for all future sessions|always add.{0,80}every project",
            ),
        ];
        Ok(Self {
            rules: patterns
                .into_iter()
                .map(|(id, weight, pattern)| Ok((id, weight, Regex::new(pattern)?)))
                .collect::<Result<_, regex::Error>>()?,
            encoded: Regex::new(r"[A-Za-z0-9+/_-]{24,}={0,2}")?,
            table_index: Regex::new(r"\|\s*\d+\s*\|")?,
            markup: Regex::new(r"[|*_>#`]+|-{3,}|\s+")?,
        })
    }

    /// Whether a rule strong enough to stand on its own matches `text`.
    fn strong_match(&self, text: &str) -> bool {
        self.rules
            .iter()
            .any(|(_, weight, regex)| *weight >= 0.7 && regex.is_match(text))
    }

    pub fn evaluate(&self, text: &str, hidden: bool) -> Verdict {
        let mut normalized = normalize(text);
        // Rejoin instructions split across table cells, quotes or lines.
        let unnumbered = self.table_index.replace_all(text, " ");
        let flattened = self.markup.replace_all(&unnumbered, " ");
        normalized.push('\n');
        normalized.push_str(&normalize(&flattened));
        let mut encoded_instruction = false;
        let rot13: String = normalized.chars().map(rot13).collect();
        if self.strong_match(&rot13) {
            encoded_instruction = true;
            normalized.push('\n');
            normalized.push_str(&rot13);
        }
        for token in self.encoded.find_iter(text).take(64) {
            if token.len() > 65_536 {
                continue;
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(token.as_str())
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(token.as_str()));
            if let Ok(decoded) = decoded
                && let Ok(decoded) = String::from_utf8(decoded)
            {
                let decoded = normalize(&decoded);
                if self.strong_match(&decoded) {
                    encoded_instruction = true;
                    normalized.push('\n');
                    normalized.push_str(&decoded);
                }
            }
        }
        let mut rules = Vec::new();
        let mut remainder = 1.0;
        for (id, weight, pattern) in &self.rules {
            if pattern.is_match(&normalized) {
                rules.push((*id).to_string());
                remainder *= 1.0 - weight;
            }
        }
        if hidden {
            rules.push("R-HIDDEN".into());
            remainder *= 0.2;
        }
        if encoded_instruction {
            rules.push("R-ENCODED".into());
            remainder *= 0.3;
        }
        Verdict {
            rule_ids: rules,
            score: 1.0 - remainder,
        }
    }
}

fn normalize(text: &str) -> String {
    text.nfkc()
        .flat_map(char::to_lowercase)
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            // Cyrillic and Greek letters that look like Latin ones.
            'а' | 'α' => 'a',
            'с' => 'c',
            'ԁ' => 'd',
            'е' | 'ε' => 'e',
            'һ' => 'h',
            'і' | 'ι' => 'i',
            'ј' => 'j',
            'κ' => 'k',
            'ӏ' => 'l',
            'о' | 'ο' => 'o',
            'р' | 'ρ' => 'p',
            'ѕ' => 's',
            'τ' => 't',
            'υ' => 'u',
            'ν' => 'v',
            'х' | 'χ' => 'x',
            'у' => 'y',
            _ => c,
        })
        .collect()
}

fn rot13(c: char) -> char {
    match c {
        'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
        'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
        _ => c,
    }
}
