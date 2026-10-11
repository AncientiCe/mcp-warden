//! Advisory heuristics. These cannot establish that arbitrary text is safe.

use base64::Engine;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

pub struct Detector {
    rules: Vec<(&'static str, f64, Regex)>,
    encoded: Regex,
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
                r"(?i)(?:ignore|disregard)\s+(?:all\s+)?(?:previous|above|prior|system)\s+instructions|ignoriere\s+alle\s+vorherigen\s+anweisungen|ignor[ăa]\s+toate\s+instruc[țt]iunile\s+anterioare|you are now|developer mode",
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
                r"(?i)webhook\.site|requestbin|interactsh|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|(?:send|post|upload)\b.{0,100}(?:https?://|secret|token|\.env|~/)",
            ),
            (
                "R-SECRETS",
                0.4,
                r"(?i)\.env\b|~/\.ssh|id_rsa|aws_secret|github_token|~/\.npmrc|read\s+(?:the\s+)?credentials",
            ),
            (
                "R-URGENCY",
                0.35,
                r"(?i)do not (?:tell|mention).{0,30}(?:user|this)|as the ai assistant you must|secretly",
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
        })
    }

    pub fn evaluate(&self, text: &str, hidden: bool) -> Verdict {
        let mut normalized = normalize(text);
        let mut encoded_instruction = false;
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
                if self
                    .rules
                    .iter()
                    .any(|(_, weight, regex)| *weight >= 0.7 && regex.is_match(&decoded))
                {
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
            _ => c,
        })
        .collect()
}
