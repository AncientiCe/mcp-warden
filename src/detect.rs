//! Advisory heuristics. These cannot establish that arbitrary text is safe.

use base64::Engine;
use regex::{Regex, RegexSet, RegexSetBuilder};
use unicode_normalization::UnicodeNormalization;

/// Longest text the whole-text ciphers (Caesar shifts, reversal, ...) are tried on.
const CIPHER_LIMIT: usize = 16 * 1024;
/// How many layers of encoding are peeled (e.g. base64 of base64, base64 of rot13).
const DECODE_DEPTH: usize = 2;

/// Opens the alternatives of a request to change who controls a repository:
/// a polite or bare imperative, not a sentence that merely talks about it.
const REQUEST: &str = r"(?:\bplease\s+|\bkindly\s+|\byou\s+(?:must|should|need\s+to)\s+|\bgo\s+ahead\s+and\s+|^\s*|[.!:]\s+|\btoken\b[^.\n]{0,60}\bto\s+)";

pub struct Detector {
    /// Rule ids and weights, in the order of `set`.
    rules: Vec<(&'static str, f64)>,
    set: RegexSet,
    encoded: Regex,
    hex: Regex,
    base32: Regex,
    morse: Regex,
    html_entity: Regex,
    json_escape: Regex,
    percent: Regex,
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
        let repo_admin = format!(
            r"(?im){REQUEST}(?:(?:delete|transfer|archive)\s+(?:this|the)\s+repo(?:sitory)?\b|(?:disable|remove|turn\s+off|bypass)\s+(?:the\s+)?branch\s+protection|(?:add|invite)\b[^.\n]{{0,60}}\b(?:as\s+an?\s+|with\s+(?:the\s+)?)(?:admin|owner)\b|add\s+(?:this|a|the)\s+deploy\s+key[^.\n]{{0,30}}\bwrite|install\s+the\s+github\s+app\b[^\n]{{0,160}}\badministration)"
        );
        let patterns: Vec<(&'static str, f64, String)> = vec![
            (
                "R-OVERRIDE",
                0.75,
                r"(?i)(?:ignore|disregard)\s+(?:all\s+)?(?:previous|above|prior|system)\s+instructions|\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:your\s+)?(?:previous|prior|earlier|preceding|above)\s+(?:steps|tasks|directions|rules|guidance|context|prompts?)\b|ignoriere\s+alle\s+vorherigen\s+anweisungen|ignor[ăa]\s+toate\s+instruc[țt]iunile\s+anterioare|ignore[rz]?\s+toutes\s+les\s+instructions\s+pr[ée]c[ée]dentes|ignora\s+(?:todas\s+)?las\s+instrucciones\s+anteriores|ignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti|ignor[ea]\s+(?:todas\s+)?as\s+instru[çc][õo]es\s+anteriores|you are now|developer mode|\bnew\s+(?:priority|instructions?|directive|objective)\s*:|\b(?:outranks|overrides|supersedes|takes\s+precedence\s+over)\s+(?:the\s+|your\s+|any\s+)?(?:user|previous|prior|system|original|earlier)\b".into(),
            ),
            (
                "R-ROLE",
                0.7,
                r"(?im)<\|im_start\|>|</?untrusted\b|^\s*###\s*system\b|\[inst\]|^\s*(?:human|assistant):".into(),
            ),
            (
                "R-TOOLCALL",
                0.2,
                r"(?i)\b(?:curl|wget|invoke-webrequest|irm|iwr|powershell\s+-enc|git\s+push)\b".into(),
            ),
            // Services that exist to collect requests: an attacker's drop box.
            (
                "R-COLLECTOR",
                0.5,
                r"(?i)webhook\.site|requestbin|interactsh|pipedream\.net|burpcollaborator|canarytokens|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com".into(),
            ),
            // Sending something out: to an address, into a reply or comment, or a public place.
            (
                "R-EXFIL",
                0.4,
                r"(?i)\b(?:send|post|upload|paste|submit|e-?mail|forward|exfiltrate|leak|transmit)\s+(?:it|them|this|that|these|those|the\s+(?:output|response|results?|contents?|body|text|files?|data|logs?|conversation))\b(?:[^.\n]|\.\S){0,60}(?:https?://|mailto:|\b[\w.-]+@[\w-]+\.[a-z]{2,})|\b(?:send|post|upload|paste|submit|e-?mail|forward|share|leak)\s+(?:the\s+|your\s+|my\s+|this\s+|all\s+|any\s+|every\s+)?(?:[\w.-]+\s+){0,3}?(?:secrets?|tokens?|\.env|env\s+file|credentials?|private\s+keys?|passwords?|id_rsa)\b|\b(?:paste|post|share|include|print|dump|quote|echo|store|reply\s+with)\b.{0,100}(?:as\s+a\s+comment|in\s+a\s+comment|on\s+this\s+issue|in\s+this\s+issue|into\s+this\s+issue|as\s+a\s+reply|in\s+(?:your|the)\s+(?:reply|response|answer)|(?:in|into)\s+the\s+chat)|\bpaste\b.{0,60}\bhere\b|\b(?:post|reply\s+with)\s+(?:it|them)\s+here\b|\bexfiltrat|\b(?:gist|paste\s?bin|paste\s+site|pull\s+request|issue|comment)\b.{0,30}\b(?:whose|with|where)\s+(?:the\s+)?(?:body|contents?|description|text)\s+(?:is|are|contains?)\b|\bpublic\s+gist\b|\bmailto:\S*[?&](?:body|subject)=|\b(?:fetch|curl|get|request|open|read|cat|log|record)\b.{0,120}\b(?:and|then)\s+(?:paste|post|share|reply)\b".into(),
            ),
            (
                "R-SECRETS",
                0.4,
                r"(?i)\.env\b|\benv\s+file\b|~/\.ssh|\.ssh/|id_rsa|id_ed25519|aws_secret|github_token|~/\.npmrc|read\s+(?:the\s+)?credentials|\.aws/(?:credentials|sso)|\.netrc\b|\.git-credentials|\.docker/config\.json|\.kube/config|\.(?:bash|zsh)_history|gh/hosts\.yml|application_default_credentials|\.azure/(?:accesstokens|msal)|library/keychains|credential\s+manager|cookie\s+(?:store|jar)|/var/run/secrets|serviceaccount/token|\.pem\b|cloud\s+tokens?|\b(?:every|all)\s+(?:the\s+)?(?:tokens?|secrets?|credentials?|api\s+keys?|passwords?)\b|authorization\s+header|bearer\s+token|authorization\s+code|oauth\s+code|system\s+prompt|developer\s+messages?|hidden\s+instructions|\b(?:whole|entire|full)\s+(?:conversation|chat|transcript)\b".into(),
            ),
            // Cloud instance metadata: where a server-side request finds credentials.
            (
                "R-METADATA",
                0.4,
                r"(?i)169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|computemetadata|metadata-flavor|fd00:ec2::254".into(),
            ),
            (
                "R-URGENCY",
                0.35,
                r"(?i)do not (?:tell|mention) (?:anyone|this)|as the ai assistant you must|secretly".into(),
            ),
            // Asking the agent to hide something from the person it works for.
            (
                "R-SECRECY",
                0.6,
                r"(?i)\b(?:do not|don['’]?t|never)\s+(?:tell|mention|inform|show|reveal)\b.{0,40}\b(?:the user|the human|your user|the owner)\b|\bwithout (?:telling|informing|notifying|asking) (?:the user|the human|your user)\b|\bkeep (?:this|it) (?:secret|hidden|private) from\b|\b(?:hide|conceal) (?:this|it) from (?:the user|the human|your user)\b|\b(?:and|then)\s+(?:do\s+not|don['’]?t|never)\s+(?:mention|tell|report|disclose)\s+(?:it|this|that)\b|\bdo\s+not\s+mention\s+that\s+you\b".into(),
            ),
            // Settings that let an agent act without asking: nobody needs these in a bug report.
            (
                "R-AGENTCFG",
                0.5,
                r#"(?i)\bauto[_-]?approve\b|\bauto[_-]?accept[_-]?edits\b|skip[_-]?permissions|bypass[_-]?permissions|\byolo\b|--full-auto\b|approval[_-]?policy\s*[:=]\s*["']?never"#.into(),
            ),
            (
                "R-MEMORY",
                0.8,
                r"(?i)remember for all future sessions|always add.{0,80}every project".into(),
            ),
            // "Decode this and follow it": hidden text the agent is told to obey.
            (
                "R-DECODE",
                0.6,
                r"(?i)\b(?:decode|decipher|decrypt|unscramble|rot13)\b[^\n]{0,80}\b(?:and|then)\s+(?:follow|obey|execute|run|carry\s+out|do|apply|act\s+on)\b|\b(?:read|release|translate|reverse)\b[^\n]{0,80}\b(?:and|then)\s+(?:follow|obey|carry\s+out|act\s+on)\b|\bfirst\s+letters?\s+of\s+(?:each|every)\s+(?:line|word|sentence|paragraph)\b".into(),
            ),
            ("R-REPOADMIN", 0.5, repo_admin),
            (
                "R-PUSH",
                0.3,
                r"(?i)\bpush\b.{0,40}\bto\s+(?:main|master)\b|\bpush\s+(?:\S+\s+)?\S*:(?:refs/heads/)?(?:main|master)\b|\bforce[- ]push|\bpush\s+--force|\bclose\b.{0,40}\b(?:and|then)\s+push\b".into(),
            ),
            (
                "R-NOREVIEW",
                0.35,
                r"(?i)\bskip\s+(?:the\s+)?(?:review|approval|checks)\b|\bwithout\s+(?:a\s+)?(?:review|approval|asking)\b|\bcannot\s+wait\s+for\s+(?:a\s+)?review|\bdo\s+not\s+ask\s+(?:the\s+user|anyone|for\s+(?:approval|confirmation))".into(),
            ),
            // Telling the agent a warning is wrong so it acts anyway.
            (
                "R-DISMISS",
                0.35,
                r"(?i)\b(?:advisory|warning|alert|scanner|audit|cve)\b.{0,40}\b(?:is|are)\s+(?:a\s+)?false\s+positives?\b|\bis\s+wrong\s+to\s+flag\b|\bignore\s+(?:the\s+)?(?:advisory|advisories|security\s+warnings?|audit)\b".into(),
            ),
            (
                "R-REGISTRY",
                0.35,
                r#"(?i)--extra-index-url|--index-url\s+https?://|\bfrom\s+https?://registry\.|<repository>|packagesources|helm\s+repo\s+add|source\s*=\s*["']git::|\bgit\s*=\s*["']https?://|npm\s+config\s+set\s+registry|\bsha256\s+["']0{64}["']"#.into(),
            ),
            (
                "R-REMOTEINSTALL",
                0.35,
                r"(?i)\|\s*(?:sudo\s+)?(?:sh|bash|zsh|iex|invoke-expression)\b|\birm\b[^\n]{0,200}\biex\b|\bclone\b.{0,120}\b(?:and|then)\s+run\b|\brun\s+(?:its|the)\s+(?:install|build|setup|postinstall)\s+script\b|\bhelm\s+install\b".into(),
            ),
            // A change to a dependency manifest or CI file, asked for by an outsider.
            (
                "R-MANIFEST",
                0.3,
                r"(?i)\b(?:apply|make)\s+(?:this|these|the\s+following)\s+(?:changes?|patch|edits?|diff)\s+(?:to|in)\s+(?:the\s+)?(?:requirements\.txt|cargo\.toml|package\.json|pom\.xml|nuget\.config|\.npmrc|pip\.conf|pyproject\.toml|go\.mod|gemfile|build\.gradle|\.github/workflows|main\.tf|homebrew\s+formula)".into(),
            ),
            // Changing a dependency: routine on its own, a lever when someone else asks the agent.
            (
                "R-DEPEDIT",
                0.2,
                r"(?i)\b(?:bump(?:ed|s|ing)?|upgrad(?:e|ed|es|ing)|updat(?:e|ed|es|ing)|downgrad(?:e|ed|es|ing)|pin(?:ned|s)?|swap(?:ped|s)?)\b(?:[^.\n]|\.\S){0,60}\b(?:deps?|dependenc(?:y|ies)|packages?|crates?|package\.json|cargo\.toml|requirements\.txt|go\.mod|pyproject\.toml|gemfile|lockfile)\b".into(),
            ),
            // Pointing something at a repository on a code host: how a fork replaces a dependency.
            (
                "R-DEPSOURCE",
                0.3,
                r"(?i)\b(?:point|switch|repoint|redirect)\b[^.\n]{0,60}\b(?:to|at)\s+(?:https?://)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)/[\w.-]+/[\w.-]+".into(),
            ),
            // Someone else's authority claimed to the reader: "the maintainer asked you to".
            (
                "R-AUTHORITY",
                0.4,
                r"(?i)\b(?:maintainers?|owners?|admins?|repo\s+owner|project\s+leads?|security\s+team|core\s+team)\s+(?:has\s+|have\s+|already\s+)?(?:asked|wants?|wanted|requested|told|instructed|authori[sz]ed|approved|needs?)\b(?:[^.\n]|\.\S){0,60}\byou\b".into(),
            ),
            // Text that speaks to the agent reading it rather than to people.
            (
                "R-AGENTADDR",
                0.35,
                r"(?i)\b(?:note|message|instructions?|reminder|directive)\s+(?:for|to)\s+(?:the\s+|any\s+|all\s+)?(?:ai\s+|llm\s+|coding\s+)?(?:agent|assistant|bot|model|ai|llm|copilot|claude|codex|cursor)s?\b|\b(?:ai|llm|coding)\s+(?:agents?|assistants?|models?)\s+(?:reading|processing|triaging|summari[sz]ing)\s+this\b|\bif\s+you\s+are\s+an?\s+(?:ai|llm|language\s+model|agent|assistant|bot)\b|\bdear\s+(?:ai|llm|agent|assistant|claude|copilot)\b".into(),
            ),
            // Work slipped in ahead of the agent's own task on this content.
            (
                "R-PRETASK",
                0.3,
                r"(?i)\b(?:before|instead\s+of|prior\s+to)\s+(?:you\s+)?(?:summari[sz](?:e|ing)|triag(?:e|ing)|review(?:ing)?|reply(?:ing)?|respond(?:ing)?|answer(?:ing)?|analy[sz](?:e|ing)|label(?:l?ing)?)\s+(?:this|the)\s+(?:issue|pr|pull\s+request|ticket|report|bug|thread|page|email|message)\b".into(),
            ),
            // Commands that switch off, reveal or erase mcp-warden itself.
            (
                "R-WARDEN",
                0.4,
                r"(?i)\bmcp-warden(?:\.exe)?\s+(?:uninstall|trust|distrust|release|show|untaint|approve)\b|~/\.mcp-warden|\.mcp-warden[/\\]".into(),
            ),
            (
                "R-COVER",
                0.4,
                r"(?i)\bleaves?\s+no\s+(?:audit\s+)?trail|\bno\s+audit\s+trail|\bcover\s+(?:your|the|its)\s+tracks|\b(?:delete|erase|wipe)\s+(?:the\s+)?(?:local\s+)?audit\s+logs?|\bclear\s+(?:the\s+)?shell\s+history".into(),
            ),
            (
                "R-STANDING",
                0.4,
                r"(?i)\balways\s+also\b|\b(?:from\s+now\s+on|every\s+time|whenever)\b.{0,60}\b(?:send|forward|copy|upload|post|bcc)\b".into(),
            ),
            (
                "R-PRIVILEGE",
                0.4,
                r"(?i)\bdelete_repo\b|\badmin:(?:org|repo_hook|enterprise)\b|\b(?:mint|create|generate|issue)\s+(?:a\s+)?new\s+(?:token|pat|api\s+key|credential)\b".into(),
            ),
            (
                "R-CREDREQ",
                0.35,
                r"(?i)\b(?:enter|paste|provide|give|type|share|send|submit)\s+(?:me\s+)?(?:your|the)\s+(?:\w+\s+){0,2}(?:personal\s+access\s+token|access\s+token|api\s+key|password|passphrase|private\s+key|recovery\s+codes?|seed\s+phrase)".into(),
            ),
            // A protocol message pasted into content, posing as the client or server.
            (
                "R-PROTOCOL",
                0.4,
                r#"(?i)"method"\s*:\s*"(?:elicitation/create|sampling/createmessage|roots/list|tools/call|resources/read)""#.into(),
            ),
            (
                "R-LOOP",
                0.5,
                r"(?i)\bcall\b.{0,40}\b(?:tool|api|function|endpoint)\b.{0,40}\b(?:\d{3,}|hundred|thousand|million)\s+times\b|\b(?:ten|a|one)\s+(?:hundred\s+)?thousand\s+times\b|\bdo\s+not\s+stop\s+(?:early|until)\b|\bloop\s+(?:forever|indefinitely)\b".into(),
            ),
            // A link whose host mixes Latin with look-alike letters, or is punycode.
            // Only the original text keeps this evidence; normalization folds it away.
            (
                "R-LOOKALIKE",
                0.45,
                r"(?i)https?://[^\s/]*(?:[a-z][^\s/]*[\p{Cyrillic}\p{Greek}]|[\p{Cyrillic}\p{Greek}][^\s/]*[a-z])|https?://(?:[^\s/]*\.)?xn--".into(),
            ),
        ];
        Ok(Self {
            // ASCII word boundaries and a roomy DFA cache keep large outputs
            // (long changelogs, web pages) on the fast engine.
            set: RegexSetBuilder::new(
                patterns
                    .iter()
                    .map(|(_, _, pattern)| pattern.replace(r"\b", r"(?-u:\b)")),
            )
            .dfa_size_limit(64 << 20)
            .build()?,
            rules: patterns
                .iter()
                .map(|(id, weight, _)| (*id, *weight))
                .collect(),
            encoded: Regex::new(r"[A-Za-z0-9+/_-]{24,}={0,2}")?,
            hex: Regex::new(r"\b(?:[0-9a-fA-F]{2}){12,}\b")?,
            base32: Regex::new(r"\b[A-Z2-7]{16,}=*")?,
            morse: Regex::new(r"(?:[.-]{1,7}[ /]+){8,}[.-]{1,7}")?,
            html_entity: Regex::new(r"&#(?:[xX]([0-9a-fA-F]{1,6})|([0-9]{1,7}));")?,
            json_escape: Regex::new(r"\\u([0-9a-fA-F]{4})")?,
            percent: Regex::new(r"%([0-9A-Fa-f]{2})")?,
            table_index: Regex::new(r"\|\s*\d+\s*\|")?,
            markup: Regex::new(r"[|*_>#`]+|-{3,}|\s+")?,
        })
    }

    /// Rules matching a `view` of the text, and their combined score.
    fn score(&self, text: &str) -> (Vec<&'static str>, f64) {
        let mut ids = Vec::new();
        let mut remainder = 1.0;
        for index in self.set.matches(text).iter() {
            let (id, weight) = self.rules[index];
            ids.push(id);
            remainder *= 1.0 - weight;
        }
        (ids, 1.0 - remainder)
    }

    pub fn evaluate(&self, text: &str, hidden: bool) -> Verdict {
        let mut normalized = view(text);
        // Rejoin instructions split across table cells, quotes or lines.
        let unnumbered = self.table_index.replace_all(text, " ");
        let flattened = self.markup.replace_all(&unnumbered, " ");
        normalized.push('\n');
        normalized.push_str(&normalize(&flattened));
        // Encoded or enciphered text counts when what it decodes to would be
        // flagged on its own.
        let mut encoded_instruction = false;
        let mut layer = vec![text.to_string()];
        for _ in 0..DECODE_DEPTH {
            let mut next = Vec::new();
            for source in &layer {
                let (decoded, deciphered) = self.decodings(source);
                for candidate in decoded.iter().chain(&deciphered) {
                    let plain = view(candidate);
                    if self.score(&plain).1 >= 0.5 {
                        encoded_instruction = true;
                        normalized.push('\n');
                        normalized.push_str(&plain);
                    }
                }
                // Only decoded text is peeled again; a cipher of a cipher is noise.
                next.extend(decoded);
            }
            layer = next;
        }
        let (ids, score) = self.score(&normalized);
        let mut rules: Vec<String> = ids.into_iter().map(String::from).collect();
        let mut remainder = 1.0 - score;
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

    /// Readable text hidden in `text` by one layer of encoding, and the text
    /// read through each cipher (every Caesar shift, Atbash, reversal, ...).
    fn decodings(&self, text: &str) -> (Vec<String>, Vec<String>) {
        let mut out = Vec::new();
        for token in self.encoded.find_iter(text).take(64) {
            if token.len() > 65_536 {
                continue;
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(token.as_str())
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(token.as_str()));
            out.extend(decoded.ok().and_then(readable));
        }
        for token in self.hex.find_iter(text).take(64) {
            out.extend(hex::decode(token.as_str()).ok().and_then(readable));
        }
        for token in self.base32.find_iter(text).take(64) {
            out.extend(base32(token.as_str()).and_then(readable));
        }
        for token in self.morse.find_iter(text).take(16) {
            out.extend(morse(token.as_str()));
        }
        if self.html_entity.find_iter(text).nth(3).is_some() {
            out.push(
                self.html_entity
                    .replace_all(text, |c: &regex::Captures| {
                        let code = match (c.get(1), c.get(2)) {
                            (Some(h), _) => u32::from_str_radix(h.as_str(), 16).ok(),
                            (_, Some(d)) => d.as_str().parse().ok(),
                            _ => None,
                        };
                        code.and_then(char::from_u32)
                            .map(String::from)
                            .unwrap_or_default()
                    })
                    .into_owned(),
            );
        }
        if self.json_escape.find_iter(text).nth(3).is_some() {
            out.push(
                self.json_escape
                    .replace_all(text, |c: &regex::Captures| {
                        u32::from_str_radix(&c[1], 16)
                            .ok()
                            .and_then(char::from_u32)
                            .map(String::from)
                            .unwrap_or_default()
                    })
                    .into_owned(),
            );
        }
        if self.percent.find_iter(text).nth(5).is_some() {
            let bytes = percent_decode(text);
            out.extend(readable(bytes));
        }
        out.extend(offset_letters(text));
        let mut ciphers = Vec::new();
        if text.len() <= CIPHER_LIMIT {
            for shift in 1..26 {
                ciphers.push(text.chars().map(|c| caesar(c, shift)).collect());
            }
            ciphers.push(text.chars().map(atbash).collect());
            ciphers.push(text.chars().rev().collect());
            ciphers.extend(pig_latin(text));
            ciphers.extend(acrostic(text));
        }
        (out, ciphers)
    }
}

/// Mostly printable UTF-8, or nothing: random bytes are not hidden text.
fn readable(bytes: Vec<u8>) -> Option<String> {
    let text = String::from_utf8(bytes).ok()?;
    let total = text.chars().count();
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    (total >= 4 && printable * 10 >= total * 9).then_some(text)
}

fn base32(token: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in token.trim_end_matches('=').chars() {
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex_pair = bytes
            .get(i + 1..i + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[i], hex_pair) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

fn morse(code: &str) -> Option<String> {
    const TABLE: &[(&str, char)] = &[
        (".-", 'a'),
        ("-...", 'b'),
        ("-.-.", 'c'),
        ("-..", 'd'),
        (".", 'e'),
        ("..-.", 'f'),
        ("--.", 'g'),
        ("....", 'h'),
        ("..", 'i'),
        (".---", 'j'),
        ("-.-", 'k'),
        (".-..", 'l'),
        ("--", 'm'),
        ("-.", 'n'),
        ("---", 'o'),
        (".--.", 'p'),
        ("--.-", 'q'),
        (".-.", 'r'),
        ("...", 's'),
        ("-", 't'),
        ("..-", 'u'),
        ("...-", 'v'),
        (".--", 'w'),
        ("-..-", 'x'),
        ("-.--", 'y'),
        ("--..", 'z'),
        ("-----", '0'),
        (".----", '1'),
        ("..---", '2'),
        ("...--", '3'),
        ("....-", '4'),
        (".....", '5'),
        ("-....", '6'),
        ("--...", '7'),
        ("---..", '8'),
        ("----.", '9'),
        (".-.-.-", '.'),
        ("--..--", ','),
        ("---...", ':'),
        ("-..-.", '/'),
        ("-....-", '-'),
        (".--.-.", '@'),
        ("..--.-", '_'),
        ("..--..", '?'),
    ];
    let words: Vec<String> = code
        .split('/')
        .map(|word| {
            word.split_whitespace()
                .map(|symbol| {
                    TABLE
                        .iter()
                        .find(|(m, _)| *m == symbol)
                        .map_or('?', |(_, c)| *c)
                })
                .collect()
        })
        .collect();
    let text = words.join(" ");
    (text.chars().filter(|c| *c == '?').count() * 4 < text.len()).then_some(text)
}

/// Letters moved to another Unicode block one-for-one: grade-1 Braille and
/// private-use characters at U+E000 plus the ASCII code.
fn offset_letters(text: &str) -> Option<String> {
    const BRAILLE: &[(u32, char)] = &[
        (0x2801, 'a'),
        (0x2803, 'b'),
        (0x2809, 'c'),
        (0x2819, 'd'),
        (0x2811, 'e'),
        (0x280B, 'f'),
        (0x281B, 'g'),
        (0x2813, 'h'),
        (0x280A, 'i'),
        (0x281A, 'j'),
        (0x2805, 'k'),
        (0x2807, 'l'),
        (0x280D, 'm'),
        (0x281D, 'n'),
        (0x2815, 'o'),
        (0x280F, 'p'),
        (0x281F, 'q'),
        (0x2817, 'r'),
        (0x280E, 's'),
        (0x281E, 't'),
        (0x2825, 'u'),
        (0x2827, 'v'),
        (0x283A, 'w'),
        (0x282D, 'x'),
        (0x283D, 'y'),
        (0x2835, 'z'),
        (0x2832, '.'),
        (0x2802, ','),
        (0x2800, ' '),
    ];
    let shifted = text
        .chars()
        .filter(|c| matches!(*c as u32, 0x2800..=0x283F | 0xE020..=0xE07E))
        .count();
    if shifted < 8 {
        return None;
    }
    Some(
        text.chars()
            .map(|c| match c as u32 {
                cp @ 0xE020..=0xE07E => char::from_u32(cp - 0xE000).unwrap_or(c),
                cp @ 0x2800..=0x283F => BRAILLE
                    .iter()
                    .find(|(b, _)| *b == cp)
                    .map_or('?', |(_, l)| *l),
                _ => c,
            })
            .collect(),
    )
}

fn caesar(c: char, shift: u8) -> char {
    match c {
        'a'..='z' => ((c as u8 - b'a' + shift) % 26 + b'a') as char,
        'A'..='Z' => ((c as u8 - b'A' + shift) % 26 + b'A') as char,
        _ => c,
    }
}

fn atbash(c: char) -> char {
    match c {
        'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
        'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
        _ => c,
    }
}

/// Pig Latin read back, line by line, moving one, two or three letters:
/// which cluster moved can't be known, so each length is tried.
fn pig_latin(text: &str) -> Vec<String> {
    let is_pig = |line: &str| {
        let words: Vec<&str> = line.split_whitespace().collect();
        let pig = words
            .iter()
            .filter(|w| {
                w.trim_matches(|c: char| !c.is_alphabetic())
                    .to_ascii_lowercase()
                    .ends_with("ay")
            })
            .count();
        words.len() >= 5 && pig * 5 >= words.len() * 2
    };
    if !text.lines().any(is_pig) {
        return Vec::new();
    }
    (1..=3)
        .map(|moved| {
            text.lines()
                .map(|line| {
                    if !is_pig(line) {
                        return line.to_string();
                    }
                    line.split_whitespace()
                        .map(|word| unpig(word, moved))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect()
}

fn unpig(word: &str, moved: usize) -> String {
    let lower = word.to_ascii_lowercase();
    let core = lower.trim_end_matches(|c: char| !c.is_alphabetic());
    if let Some(stem) = core.strip_suffix("way") {
        return stem.to_string();
    }
    match core.strip_suffix("ay") {
        Some(stem) if stem.len() > moved && stem.is_ascii() => {
            let (rest, cluster) = stem.split_at(stem.len() - moved);
            format!("{cluster}{rest}")
        }
        _ => lower.clone(),
    }
}

/// First letters of each line; blank lines become spaces.
fn acrostic(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    if lines.iter().filter(|l| !l.is_empty()).count() < 8 {
        return None;
    }
    Some(
        lines
            .iter()
            .filter_map(|line| match line.chars().next() {
                None => Some(' '),
                Some(c) if c.is_alphabetic() => Some(c),
                Some(_) => None,
            })
            .collect(),
    )
}

/// What the rules see: the normalized text, then the original, since folding
/// digits and look-alike letters also erases evidence (IP addresses, mixed scripts).
fn view(text: &str) -> String {
    format!(
        "{}
{text}",
        normalize(text)
    )
}

fn normalize(text: &str) -> String {
    text.chars()
        // Marks that split words without showing: soft hyphen, grapheme
        // joiner, directional marks. Hangul fillers render as blanks.
        .filter(|c| !matches!(*c as u32, 0xAD | 0x34F | 0x61C | 0x200E | 0x200F))
        .map(|c| match c as u32 {
            0x115F | 0x1160 | 0x3164 | 0xFFA0 => ' ',
            _ => c,
        })
        .nfkc()
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
