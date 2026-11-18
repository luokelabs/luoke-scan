package core

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Chat templates of local models (luoke-scan#79). A downloaded model carries the template its tools wrap every
// conversation in: Jinja in Hugging Face's tokenizer_config.json / chat_template.jinja and in a GGUF file's metadata,
// Go's text/template in Ollama's TEMPLATE layer, and Ollama's SYSTEM (the default system prompt) and preset MESSAGEs.
// A family's template is turn markers, roles, the tool-call format and a few fixed sentences (who the model is, a
// knowledge date). What is looked for is what those do not have: words aimed at the model (ignore your rules, speak as
// the system, keep this from the user, send the conversation away, always push something or a link), and characters
// nobody sees. Only the kinds are kept, never the text. The research and the evaluation: docs/对话模板.md.

// TemplateSyntax is how a template is written.
type TemplateSyntax int

const (
	SyntaxJinja TemplateSyntax = iota // Hugging Face, GGUF, LM Studio's MLX models
	SyntaxGo                          // Ollama's TEMPLATE
	SyntaxPlain                       // Ollama's SYSTEM and preset messages: the text is what the model gets
)

// ---------------------------------------------------------------- what reaches the model

// TemplateOutput is what of a template can reach the model, in order: the text between its tags and the string
// literals it prints or sets, one space where it prints a value. Comments, and literals only compared, used as keys or
// passed to a function (raise_exception's message, split's separator), are left out.
func TemplateOutput(src string, syntax TemplateSyntax) string {
	if syntax == SyntaxPlain {
		return src
	}
	goTpl := syntax == SyntaxGo
	var out strings.Builder
	for i := 0; i < len(src); {
		j := nextTemplateTag(src, i, goTpl)
		if j < 0 {
			out.WriteString(src[i:])
			break
		}
		out.WriteString(src[i:j])
		open := src[j : j+2]
		if open == "{#" {
			k := strings.Index(src[j+2:], "#}")
			if k < 0 {
				break
			}
			i = j + 4 + k
			continue
		}
		closer := "}}"
		if open == "{%" {
			closer = "%}"
		}
		body, end := templateTagBody(src, j+2, closer, goTpl)
		i = end
		if goTpl {
			out.WriteString(goActionOutput(body))
			continue
		}
		if open == "{{" {
			out.WriteString(templateLiterals(body, false, false))
			continue
		}
		switch templateFirstWord(body) {
		case "set": // printed where it is used; checked here
			out.WriteString(templateLiterals(body, true, false))
		case "raw": // printed as it is up to endraw
			k := jinjaEndRaw.FindStringIndex(src[i:])
			if k == nil {
				out.WriteString(src[i:])
				i = len(src)
			} else {
				out.WriteString(src[i : i+k[0]])
				i += k[1]
			}
		}
		// Other statements (if, for, macro…) print nothing; their literals are conditions.
	}
	return out.String()
}

var jinjaEndRaw = regexp.MustCompile(`\{%[-+]?\s*endraw\s*[-+]?%\}`)

func nextTemplateTag(src string, from int, goTpl bool) int {
	for i := from; i+1 < len(src); i++ {
		if src[i] != '{' {
			continue
		}
		switch src[i+1] {
		case '{':
			return i
		case '%', '#':
			if !goTpl {
				return i
			}
		}
	}
	return -1
}

// templateTagBody is a tag's inside up to its closer (not one in a string literal), and where the text after it starts.
func templateTagBody(src string, from int, closer string, goTpl bool) (string, int) {
	if goTpl {
		rest := strings.TrimLeft(src[from:], "- \t\r\n")
		if strings.HasPrefix(rest, "/*") { // a comment: {{/* … */}}
			start := len(src) - len(rest)
			k := strings.Index(src[start:], "*/")
			if k < 0 {
				return "", len(src)
			}
			c := strings.Index(src[start+k:], closer)
			if c < 0 {
				return "", len(src)
			}
			return "", start + k + c + len(closer)
		}
	}
	for i := from; i < len(src); {
		c := src[i]
		if c == '\'' || c == '"' || (goTpl && c == '`') {
			_, end := templateQuoted(src, i, goTpl)
			i = end
			continue
		}
		if strings.HasPrefix(src[i:], closer) {
			return src[from:i], i + len(closer)
		}
		i++
	}
	return src[from:], len(src)
}

// templateQuoted is the string literal starting at src[i] (a quote), its value and where it ends.
func templateQuoted(src string, i int, goTpl bool) (string, int) {
	q := src[i]
	j := i + 1
	for j < len(src) && src[j] != q {
		if src[j] == '\\' && q != '`' {
			j++
		}
		j++
	}
	if j >= len(src) {
		return "", len(src)
	}
	raw := src[i : j+1]
	if goTpl {
		if q == '\'' {
			if r, _, _, err := strconv.UnquoteChar(raw[1:len(raw)-1], '\''); err == nil {
				return string(r), j + 1
			}
			return raw[1 : len(raw)-1], j + 1
		}
		if v, err := strconv.Unquote(raw); err == nil {
			return v, j + 1
		}
		return raw[1 : len(raw)-1], j + 1
	}
	return jinjaUnescape(raw[1 : len(raw)-1]), j + 1
}

// jinjaUnescape is a Jinja string literal's value: Python's escapes (\n, \t, \\, \', \", \xhh, \uhhhh, \Uhhhhhhhh,
// octal); an unknown escape stays as written.
func jinjaUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 == len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		e := s[i]
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\\', '\'', '"':
			b.WriteByte(e)
		case '\n':
		case 'x', 'u', 'U':
			n := 2
			if e == 'u' {
				n = 4
			} else if e == 'U' {
				n = 8
			}
			if i+1+n <= len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32); err == nil && utf8.ValidRune(rune(v)) {
					b.WriteRune(rune(v))
					i += n
					continue
				}
			}
			b.WriteByte('\\')
			b.WriteByte(e)
		default:
			if e >= '0' && e <= '7' {
				j := i
				for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				v, _ := strconv.ParseUint(s[i:j], 8, 32)
				b.WriteRune(rune(v))
				i = j - 1
				continue
			}
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return b.String()
}

func templateFirstWord(body string) string {
	t := strings.TrimLeft(body, "-+ \t\r\n")
	end := 0
	for end < len(t) && (t[end] == '_' || (t[end] >= 'a' && t[end] <= 'z')) {
		end++
	}
	return t[:end]
}

// templateNotPrinted are the tokens after which a literal is not printed: compared, a key, a function's argument.
var templateNotPrinted = map[string]bool{"[": true, "(": true, ",": true, "==": true, "!=": true, "<": true, ">": true,
	"<=": true, ">=": true, "in": true, "is": true, "not": true, "and": true, "or": true, ":": true}

// templateLiterals is what an expression tag prints: its literals not compared or used as keys, joined as they are
// concatenated, one space for a value printed between or around them. set: an assignment ({% set x = '…' %}).
func templateLiterals(body string, set, goTpl bool) string {
	var b strings.Builder
	prev, gap := "", false
	next := func(i int) string { // the token after position i
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
			i++
		}
		switch {
		case i >= len(body):
			return ""
		case strings.HasPrefix(body[i:], "=="), strings.HasPrefix(body[i:], "!="):
			return body[i : i+2]
		case body[i] == ']':
			return "]"
		}
		w := templateFirstWord(body[i:])
		return w
	}
	for i := 0; i < len(body); {
		c := body[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'' || c == '"' || (goTpl && c == '`'):
			v, end := templateQuoted(body, i, goTpl)
			after := next(end)
			drop := templateNotPrinted[prev] || (prev == "=" && !set) || after == "==" || after == "!=" || after == "]" ||
				after == "in" || after == "is"
			if !drop {
				if gap && b.Len() > 0 {
					b.WriteByte(' ')
				}
				b.WriteString(v)
				gap = false
			}
			prev, i = "lit", end
		case c == '_' || c == '.' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			j := i
			for j < len(body) && (body[j] == '_' || body[j] == '.' || body[j] == '$' || (body[j] >= 'a' && body[j] <= 'z') ||
				(body[j] >= 'A' && body[j] <= 'Z') || (body[j] >= '0' && body[j] <= '9')) {
				j++
			}
			w := body[i:j]
			switch w {
			case "in", "is", "not", "and", "or", "if", "else", "set":
			default:
				if prev != "|" { // a filter's name prints nothing of its own
					gap = true
				}
			}
			prev, i = w, j
		default:
			op := string(c)
			if i+1 < len(body) && body[i+1] == '=' && strings.ContainsRune("=!<>", rune(c)) {
				op = body[i : i+2]
			}
			prev, i = op, i+len(op)
		}
	}
	if gap {
		b.WriteByte(' ')
	}
	return b.String()
}

// goControl are the actions of Go's text/template that print nothing.
var goControl = map[string]bool{"if": true, "else": true, "range": true, "with": true, "end": true, "define": true,
	"template": true, "block": true, "break": true, "continue": true}

// goCompare are its functions whose string arguments are compared, not printed; goAssign, an action that only sets a
// variable.
var (
	goCompare = regexp.MustCompile(`(?:^|[\s(])(?:eq|ne|lt|le|gt|ge|index|slice|len|and|or|not)\s`)
	goAssign  = regexp.MustCompile(`^\$\w*\s*:?=`)
)

// goActionOutput is what an action of an Ollama template prints.
func goActionOutput(body string) string {
	t := strings.Trim(body, "- \t\r\n")
	if goControl[templateFirstWord(t)] || goAssign.MatchString(t) {
		return ""
	}
	if goCompare.MatchString(" " + t) {
		return " "
	}
	return templateLiterals(t, false, true)
}

// ---------------------------------------------------------------- what is looked for

// TemplateKind is a kind of words to the model a template should not have.
type TemplateKind string

const (
	TplIgnore      TemplateKind = "ignore-rules"
	TplImpersonate TemplateKind = "impersonate"
	TplConceal     TemplateKind = "conceal"
	TplExfil       TemplateKind = "exfil"
	TplSteer       TemplateKind = "steer"
	TplHidden      TemplateKind = "hidden"
)

// templateKindOrder: the most serious first.
var templateKindOrder = []TemplateKind{TplExfil, TplConceal, TplIgnore, TplImpersonate, TplSteer, TplHidden}

var templateKindLabels = map[TemplateKind]string{
	TplIgnore:      "让模型不管原来的指令",
	TplImpersonate: "冒充系统或开发者说话",
	TplConceal:     "让模型瞒着你或骗你",
	TplExfil:       "让模型把对话或资料发出去",
	TplSteer:       "让模型总推荐某样东西或附上链接",
	TplHidden:      "藏着看不见的字符",
}

// TemplateKindLabel says a kind in words.
func TemplateKindLabel(k TemplateKind) string { return templateKindLabels[k] }

// TemplateCheck is what a check found: the kinds, most serious first, and how serious: High for words to the model or
// tag characters (they spell out text only the model reads), Medium for other invisible characters alone, "" none.
type TemplateCheck struct {
	Kinds    []TemplateKind
	Severity Severity
}

// CheckChatTemplate checks what of a template reaches the model.
func CheckChatTemplate(src string, syntax TemplateSyntax) TemplateCheck {
	return CheckTemplateText(TemplateOutput(src, syntax))
}

// CheckTemplateText checks text as the model gets it: line by line, invisible characters taken out first (and what
// tag characters spell, checked too).
func CheckTemplateText(text string) TemplateCheck {
	found := map[TemplateKind]bool{}
	words, tags, bidi, zeroWidth := false, false, 0, 0
	add := func(ks []TemplateKind) {
		for _, k := range ks {
			found[k], words = true, true
		}
	}
	for _, line := range strings.Split(text, "\n") {
		inv := skillInvisible([]rune(strings.TrimSuffix(line, "\r")), false)
		if len(inv.tags) > 0 {
			tags = true
			for _, l := range strings.Split(string(inv.tags), "\n") {
				add(templateWordsLong(l))
			}
		}
		bidi += inv.bidi
		zeroWidth += inv.zeroWidth
		add(templateWordsLong(string(inv.clean)))
	}
	if tags || bidi > 0 || zeroWidth >= 3 { // as the skills' check: one or two zero-width characters are copy-paste
		found[TplHidden] = true
	}
	var c TemplateCheck
	for _, k := range templateKindOrder {
		if found[k] {
			c.Kinds = append(c.Kinds, k)
		}
	}
	switch {
	case words || tags:
		c.Severity = High
	case len(c.Kinds) > 0:
		c.Severity = Medium
	}
	return c
}

// templateWordsLong checks a long line in overlapping pieces (a template's JSON-like lines run to thousands of
// characters; the patterns look within a sentence).
func templateWordsLong(line string) []TemplateKind {
	const piece, overlap = 4000, 400
	r := []rune(line)
	if len(r) <= piece {
		return templateWords(line)
	}
	var out []TemplateKind
	for i := 0; i < len(r); i += piece - overlap {
		out = append(out, templateWords(string(r[i:min(i+piece, len(r))]))...)
		if i+piece >= len(r) {
			break
		}
	}
	return out
}

// templateMarkers are turn and tool markers of the families (<|im_start|>, <|start_header_id|>, <｜User｜>,
// <start_of_turn>, <tool_call>, [INST], [SYSTEM_PROMPT], <<SYS>>…): format, not words.
var templateMarkers = regexp.MustCompile(`<\|[^|<>\n]{0,40}\|>|<｜[^｜\n]{0,40}｜>|</?[A-Za-z_][A-Za-z0-9_-]{0,30}\|?>|\[/?[A-Z][A-Z_]{1,30}\]|<</?SYS>>|\[gMASK\]`)

// templatePlain is a line as the patterns see it: markers out, white space as one space, lower case.
func templatePlain(s string) string {
	s = templateMarkers.ReplaceAllString(s, " ")
	return aiLower(strings.Join(strings.Fields(s), " "))
}

// templateKnownSentences are the families' own sentences: default system prompts, knowledge and date lines, how to call
// a tool. Taken out of a line before it is checked, so a family's own words never count, whatever a pattern might
// make of them; what is added to them still does.
var templateKnownSentences = []string{
	// Qwen
	"You are Qwen, created by Alibaba Cloud. You are a helpful assistant.",
	"You are a helpful assistant.",
	"You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step.",
	"Please reason step by step, and put your final answer within \\boxed{}.",
	"You may call one or more functions to assist with the user query.",
	"You are provided with function signatures within <tools></tools> XML tags:",
	"For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:",
	// Qwen3.5 and Qwen3-Coder (tool calls as <function=…><parameter=…>)
	"You have access to the following functions:",
	"If you choose to call a function ONLY reply in the following format with NO suffix:",
	"Reminder:",
	"- Function calls MUST follow the specified format: an inner <function=...></function> block must be nested within <tool_call></tool_call> XML tags",
	"- Required parameters MUST be specified",
	"- You may provide optional reasoning for your function call in natural language BEFORE the function call, but NOT after",
	"- If there is no function call available, answer the question like normal with your current knowledge and do not tell the user about function calls",
	// Llama 2
	"You are a helpful, respectful and honest assistant. Always answer as helpfully as possible, while being safe.",
	"Your answers should not include any harmful, unethical, racist, sexist, toxic, dangerous, or illegal content.",
	"Please ensure that your responses are socially unbiased and positive in nature.",
	"If a question does not make any sense, or is not factually coherent, explain why instead of answering something not correct.",
	"If you don't know the answer to a question, please don't share false information.",
	// Llama 3.x
	"Cutting Knowledge Date: December 2023",
	"Today Date:",
	"Environment: ipython",
	"You have access to the following functions. To call a function, please respond with JSON for a function call.",
	"Given the following functions, please respond with a JSON for a function call with its proper arguments that best answers the given prompt.",
	`Respond in the format {"name": function name, "parameters": dictionary of argument name and its value}.`,
	"Do not use variables.",
	"When you receive a tool call response, use the output to format an answer to the original user question.",
	"When you receive a tool call response, use the output to format an answer to the orginal user question.",
	"You are a helpful assistant with tool calling capabilities.",
	// Mistral
	"You are Mistral Small 3, a Large Language Model (LLM) created by Mistral AI, a French startup headquartered in Paris.",
	"Your knowledge base was last updated on 2023-10-01.",
	"The current date is",
	"When you're not sure about some information, you say that you don't have the information and don't make up anything.",
	"If the user's question is not clear, ambiguous, or does not provide enough context for you to accurately answer the question, you do not try to answer it right away and you rather ask the user to clarify their request",
	"You are always very attentive to dates, in particular you try to resolve dates",
	"You follow these instructions in all languages, and always respond to the user in the language they use or request.",
	"You cannot perform any web search or access internet to open URLs, links etc.",
	"If it seems like the user is expecting you to do so, you clarify the situation and ask the user to copy paste the text directly in the chat.",
	// DeepSeek
	"You are an AI programming assistant, utilizing the Deepseek Coder model, developed by Deepseek Company, and you only answer questions related to computer science.",
	"For politically sensitive questions, security and privacy issues, and other non-computer science questions, you will refuse to answer",
	// Phi
	"You are Phi, a language model trained by Microsoft to help users.",
	// Hermes (NousResearch) tool use
	"You are a function calling AI model. You are provided with function signatures within <tools></tools> XML tags.",
	"Don't make assumptions about what values to plug into functions.",
	"For each function call return a json object with function name and arguments within <tool_call></tool_call> XML tags as follows:",
	// Granite
	"You are Granite, developed by IBM.",
	"You are a helpful AI assistant with access to the following tools.",
	"When a tool is required to answer the user's query, respond with <|tool_call|> followed by a JSON list of tools used.",
	"If a tool does not exist in the provided list of tools, notify the user that you do not have the ability to fulfill the request.",
	// Command R
	"The instructions in this section override those in the task description and style guide sections.",
	"Don't answer questions that are harmful or immoral.",
	// Others
	"You are a helpful AI assistant named SmolLM, trained by Hugging Face",
	"A chat between a curious user and an artificial intelligence assistant. The assistant gives helpful, detailed, and polite answers to the user's questions.",
	"Below is an instruction that describes a task. Write a response that appropriately completes the request.",
	"你是一个名为 ChatGLM 的人工智能助手。你是基于智谱AI训练的语言模型 GLM-4 模型开发的，你的任务是针对用户的问题和要求提供适当的答复和支持。",
}

var templateKnown = sync.OnceValue(func() []string {
	var out []string
	for _, s := range templateKnownSentences {
		if p := templatePlain(s); p != "" {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
})

// templateSkillPatterns are the skills' checks for words aimed at an AI (skillcheck.go: ignore the rules, speak as the
// system or the developers, keep it from the user), without the one for chat-template markers: a template is made of
// them.
var templateSkillPatterns = sync.OnceValue(func() []skillPattern {
	var out []skillPattern
	for _, p := range skc().patterns {
		if (p.role == roleInjection || p.role == roleConceal) && !p.outsideCode {
			out = append(out, p)
		}
	}
	return out
})

type templatePattern struct {
	kind TemplateKind
	re   *regexp.Regexp
	// unless: not when this is on the line too.
	unless *regexp.Regexp
}

func tp(kind TemplateKind, re string, unless string) templatePattern {
	p := templatePattern{kind: kind, re: regexp.MustCompile(`(?i)` + re)}
	if unless != "" {
		p.unless = regexp.MustCompile(`(?i)` + unless)
	}
	return p
}

// A web address in what reaches the model (no family's template has one), after a word that sends people there or
// puts it in answers.
const templateURL = `(?:https?://|\bwww\.)`

// What a model has to be told to work against its user, beyond the skills' patterns. Lines are lower case.
var templatePatterns = []templatePattern{
	// Send the conversation or the user's data somewhere. Each marks the verb (at; for 把…发送 also at2): what is said
	// right before it decides whether it is asked for or forbidden (templateAsked).
	tp(TplExfil, `\b(?P<at>(?:send|upload|post|forward|transmit|exfiltrat|leak|copy|submit|e-?mail|relay|report|sync|mirror|log)\w*)\b[^.\n]{0,60}?\b(?:conversations?|chat\s+(?:history|logs?|transcripts?)|message\s+history|transcripts?|everything\s+the\s+user|(?:the\s+)?user'?s?\s+(?:data|inputs?|messages?|files?|passwords?|credentials|keys?|tokens?|information|details|code|secrets?|prompts?)|personal\s+(?:data|information|details)|passwords?|credentials|api\s+keys?|secrets?|private\s+keys?)\b[^.\n]{0,80}?(?:https?://|\bwww\.|\b[\w.+-]+@[\w-]+\.[a-z]{2,}|\b(?:server|endpoint|webhook|url|address|remote|external)\b)`, ""),
	tp(TplExfil, `\b(?P<at>(?:send|upload|post|forward|transmit|submit|e-?mail|relay|report)\w*)\b[^.\n]{0,40}?(?:https?://\S+|\bwww\.\S+|\b[\w.+-]+@[\w-]+\.[a-z]{2,})[^.\n]{0,60}?\b(?:conversations?|chat\s+(?:history|logs?)|transcripts?|(?:the\s+)?user'?s?\s+(?:data|inputs?|messages?|files?|passwords?|credentials|keys?|information|code|secrets?)|passwords?|credentials|api\s+keys?|secrets?)\b`, ""),
	tp(TplExfil, `\b(?:passwords?|credentials|api\s+keys?|secrets?|private\s+keys?|(?:the\s+)?user'?s?\s+(?:data|messages?|files?|passwords?|credentials|keys?|code|secrets?)|conversations?|chat\s+(?:history|logs?)|transcripts?)\b[^.\n]{0,60}?\b(?P<at>(?:send|upload|post|forward|transmit|submit|e-?mail|relay|report|copy|leak)\w*)\b[^\n]{0,40}?(?:https?://|\bwww\.|\b[\w.+-]+@[\w-]+\.[a-z]{2,}|\b(?:server|endpoint|webhook)\b)`, ""),
	tp(TplExfil, `(?P<at>发送|上传|转发|发到|传到|抄送|提交|同步到|备份到)[^。\n]{0,30}?(?:对话|聊天记录|聊天内容|消息记录|用户(?:的)?(?:数据|资料|信息|消息|密码|文件|密钥|代码|隐私)|个人信息|隐私|密码|密钥|令牌|助记词)`, ""),
	tp(TplExfil, `(?P<at>把|将)[^。\n]{0,20}?(?:对话|聊天记录|聊天内容|用户(?:的)?(?:数据|资料|信息|消息|密码|文件|密钥|代码)|密码|密钥|令牌|助记词)[^。\n]{0,20}?(?P<at2>发送|上传|转发|发到|传到|发给|提交)`, ""),
	// Keep the instructions, or things, from the user; lie to them.
	tp(TplConceal, `\b(?:never|do\s*n[o']?t|must\s+not|should\s+not|under\s+no\s+circumstances|not\s+to)\b[^.\n]{0,20}?\b(?:reveal|disclose|mention|admit|acknowledge|discuss|repeat|share|show|explain|tell\s+(?:the\s+user\s+)?about)\w*\b[^.\n]{0,30}?\b(?:these|this|the|your|any|above|following|my)\s+(?:system\s+|hidden\s+|secret\s+)?(?:instructions?|prompts?|rules|directives?|guidelines|note|setup|configuration)\b`, ""),
	tp(TplConceal, `\b(?:lie\s+to|deceive|mislead|manipulate|trick|gaslight|misinform)\w*\s+(?:the\s+|your\s+)?(?:users?|human|people|them|customers?)\b`, ""),
	tp(TplConceal, `\bpretend\s+(?:that\s+)?(?:there\s+(?:are|is)\s+no|you\s+(?:have|got|received)\s+no)\b`, ""),
	tp(TplConceal, `(?:不要|别|不得|绝不|切勿|不可|禁止|不能)[^。\n]{0,8}?(?:透露|泄露|提及|提到|说出|告诉用户|承认|复述|公开)[^。\n]{0,6}?(?:这段话|这些话|这段设定|以上内容|上面的内容|这些指令|这条指令|系统提示|指令|指示|提示词|设定|规则)`, ""),
	tp(TplConceal, `(?:欺骗|误导|蒙骗|糊弄|哄骗|骗)(?:用户|使用者|对方|他们)`, ""),
	// Put the user's own instructions or the safety rules aside.
	tp(TplIgnore, `\b(?:ignore|disregard|override|bypass)\w*\s+(?:the\s+|any\s+|all\s+)?(?:user'?s?|their|its|operator'?s?)\s+(?:own\s+)?(?:system\s+)?(?:instructions?|requests?|prompts?|settings|messages?|rules)\b`, ""),
	tp(TplIgnore, `\btakes?\s+(?:priority|precedence)\s+over\s+(?:all|any|the)\s+(?:other\s+)?(?:user|system|developer)\b`, ""),
	tp(TplIgnore, `\b(?:system|safety)\s+(?:prompts?|rules|guidelines|instructions)\s+(?:do\s+not|don't|no\s+longer)\s+apply\b`, ""),
	tp(TplIgnore, `(?:无视|忽略|不用理会|不要理会)(?:用户|使用者)(?:的)?(?:指令|要求|设定|系统提示)`, ""),
	tp(TplImpersonate, `\b(?:new|updated)\s+(?:system|developer|admin)\s+(?:instructions?|polic(?:y|ies)|prompts?|orders?)\b`, ""),
	// Push something, or a link, on the user.
	tp(TplSteer, `\b(?:visit|click|go\s+to|open|check\s+out|sign\s+up|download|install|include|insert|append|add|share|recommend|refer|direct|link|mention|promote|send\s+(?:the\s+)?users?)\b[^\n]{0,60}?`+templateURL, ""),
	tp(TplSteer, `(?:访问|点击|打开|附上|加上|附带|插入|推荐|引导|下载|注册)[^\n]{0,30}?`+templateURL, ""),
	tp(TplSteer, `\b(?:always|only|exclusively|in\s+(?:every|each|all)\s+(?:of\s+your\s+)?(?:answers?|responses?|repl(?:y|ies)|messages?|conversations?)|at\s+the\s+end\s+of\s+(?:every|each|all|your)\s+(?:answers?|responses?|repl(?:y|ies)|messages?)|whenever\s+(?:possible|you\s+can|relevant))\b[^.\n]{0,40}?\b(?:recommend|promot|advertis|endors|upsell|shill|plug)\w*`,
		`\b(?:consult\w*|seek\w*|professional|doctor|physician|expert|lawyer|attorney|caution|safety|backups?|official\s+(?:docs|documentation|sources?))\b`),
	tp(TplSteer, `\b(?:recommend|promot|advertis|endors|mention|includ|insert|append|add|suggest|push|plug|upsell)\w*\b[^.\n]{0,40}?\b(?:sponsors?|sponsored|affiliates?|referral|discount|coupons?|promo\s*codes?|crypto(?:currenc(?:y|ies)|coins?)?|casino|betting|our\s+(?:company|app|service|store|shop|site|website|platform|products?|brand))\b`, ""),
	tp(TplSteer, `(?:总是|始终|每次|一律|务必|一定要|优先|只|都要|尽量)(?:向用户|给用户)?(?:推荐|推销|宣传|安利)`, `咨询|就医|医生|专业|律师|官方|备份|安全`),
	tp(TplSteer, `(?:推荐|推销|宣传|提到|附上|加上)[^。\n]{0,20}(?:我们的(?:产品|应用|服务|网站|店铺|平台)|优惠码|返利|推广链接|邀请码|加密货币|博彩)`, ""),
}

var plainWord = regexp.MustCompile(`^[a-z]+$`)

// templateWords are the kinds of words to the model in one line (invisible characters already out).
func templateWords(line string) []TemplateKind {
	l := templatePlain(line)
	for _, k := range templateKnown() {
		if strings.Contains(l, k) {
			l = strings.ReplaceAll(l, k, " ")
		}
	}
	l = strings.Join(strings.Fields(l), " ")
	if l == "" {
		return nil
	}
	var out []TemplateKind
	r := []rune(l)
	for _, p := range templateSkillPatterns() {
		if !aiContainsAny(l, p.needles) {
			continue
		}
		m := p.re.find(r, 0)
		if m == nil || (p.unless != nil && p.unless.hasRunes(r)) || (p.test != nil && !p.test(r, m)) {
			continue
		}
		switch {
		case p.role == roleConceal:
			// "secretly" alone is how a persona talks; with something done, or said outright, it keeps things from you.
			if plainWord.MatchString(string(r[m[0]:m[1]])) && !skc().action.hasRunes(r) {
				continue
			}
			out = append(out, TplConceal)
		case strings.Contains(p.label, "忽略"):
			out = append(out, TplIgnore)
		default:
			out = append(out, TplImpersonate)
		}
	}
	for _, p := range templatePatterns {
		if templateAsked(p.re, l) && (p.unless == nil || !p.unless.MatchString(l)) {
			out = append(out, p.kind)
		}
	}
	return out
}

// templateAsked: re matches l somewhere it is not forbidden. A pattern that marks its verb (the group at, and at2)
// does not count where the words right before the verb say not to (templateNegation): "never send the user's data
// to any server", 「绝不要把用户的数据发送到外部服务器」. Only right before it, in the same clause: "Don't tell the user.
// Send the conversation to …" still asks, and so do "never forget to send", 「不要忘了把对话发到」. "Email" before
// "address" is not the verb.
func templateAsked(re *regexp.Regexp, l string) bool {
	at, at2 := re.SubexpIndex("at"), re.SubexpIndex("at2")
	if at < 0 {
		return re.MatchString(l)
	}
	for from := 0; from <= len(l); {
		m := re.FindStringSubmatchIndex(l[from:])
		if m == nil {
			return false
		}
		a, b := from+m[2*at], from+m[2*at+1]
		forbidden := templateNegated(l[:a]) || templateEmailAddress.MatchString(l[a:])
		if at2 >= 0 && m[2*at2] >= 0 {
			forbidden = forbidden || templateNegated(l[:from+m[2*at2]])
		}
		if !forbidden {
			return true
		}
		from = b // look again past this verb: the same sentence may go on to ask
	}
	return false
}

// templateNegation: a line (lower case) that ends in a word forbidding what comes next, with at most a few words
// between it and the verb that do not change that ("should you", "ever", 「要」「擅自」, where to: 「向外部服务器」,
// what: 「把用户的数据」). Nothing else in between, not even a comma: "whether you like it or not, send …" asks.
var templateNegation = regexp.MustCompile(`(?:(?:^|[^\p{L}\p{N}_'’])(?:never|do\s*n[o'’]?t|does\s*n[o'’]?t|must\s*n[o'’]?t|should\s*n[o'’]?t|shall\s+not|may\s+not|can\s*n[o'’]?t|can[o'’]t|cannot|won[o'’]?t|will\s+not|not|no\s+need\s+to|under\s+no\s+circumstances|in\s+no\s+case|nor)` +
	`(?:\s+(?:ever|actually|directly|automatically|secretly|silently|quietly|proactively|also|anymore|any\s+more|you|it|be|been|get|should|may|must|will|can|to))*` +
	`|(?:不要|(?:^|[^特区分类个级识告离辨性派鉴])别|不得|绝不|绝对不|决不|切勿|不可|禁止|不能|不会|不准|不许|不应|严禁|从不|勿|无需|不必|不用|不)` +
	`(?:要|能|可|会|得|许|准|应该|应|可以|允许|擅自|私自|主动|自动|再|随意|随便|轻易|偷偷|悄悄|直接|(?:向|给|往|对)[^，。；！？,;!?\s]{0,8}?(?:服务器|网站|网址|地址|外部|外面|外网|第三方|任何人|别人|他人|其他人|云端|任何地方|外)` +
	`|(?:把|将)[^，。；！？,;!?\s并再就然]{1,20})*)\s*$`)

// templateEmailAddress: "email" that is not the verb ("to any email address or webhook").
var templateEmailAddress = regexp.MustCompile(`^e-?mails?\s+address`)

// templateNegated: the text before a verb ends in a word forbidding it.
func templateNegated(before string) bool {
	if len(before) > 160 { // the few words before it; start at a whole character
		cut := len(before) - 160
		for cut < len(before) && !utf8.RuneStart(before[cut]) {
			cut++
		}
		before = " " + before[cut:]
	}
	return templateNegation.MatchString(before)
}

// ---------------------------------------------------------------- GGUF

// GGUFLimits bound what is read of a GGUF file: its header (the metadata) only, never the tensors.
type GGUFLimits struct {
	// MaxBytes of the header read; past it the rest is not looked at. A 262k-token vocabulary with its merges is about
	// 10 MB.
	MaxBytes    int64
	MaxEntries  uint64 // metadata entries
	MaxArray    uint64 // elements of one array
	MaxKey      uint64 // bytes of a key (the format says at most 65535)
	MaxTemplate uint64 // bytes of one template
}

// DefaultGGUFLimits: 64 MiB of header, 65536 entries, 16M elements an array, 1 MiB a template.
func DefaultGGUFLimits() GGUFLimits {
	return GGUFLimits{MaxBytes: 64 << 20, MaxEntries: 1 << 16, MaxArray: 1 << 24, MaxKey: 65535, MaxTemplate: 1 << 20}
}

// GGUFTemplates is what a GGUF file's metadata says of its chat templates.
type GGUFTemplates struct {
	// Templates: tokenizer.chat_template (under "") and the named ones (tokenizer.chat_template.<name>).
	Templates map[string]string
	// TooBig: a template, or the header before its end, was past the limits: not all of it looked at.
	TooBig bool
	// Bad: not a GGUF file this reads (version 2 or 3, little-endian), or cut short.
	Bad bool
	// Read: bytes read.
	Read int64
}

const (
	ggufString = 8
	ggufArray  = 9
)

// ggufSizes are the sizes of the fixed-size value types (uint8 … float64, bool).
var ggufSizes = map[uint32]uint64{0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}

var errGGUFOver = errors.New("past the limits")

type ggufReader struct {
	r   *bufio.Reader
	n   int64
	max int64
	buf [8]byte
	err error
}

func (g *ggufReader) fill(k int) []byte {
	if g.err != nil {
		return nil
	}
	if g.n+int64(k) > g.max {
		g.err = errGGUFOver
		return nil
	}
	if _, err := io.ReadFull(g.r, g.buf[:k]); err != nil {
		g.err = err
		return nil
	}
	g.n += int64(k)
	return g.buf[:k]
}

func (g *ggufReader) u32() uint32 {
	if b := g.fill(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (g *ggufReader) u64() uint64 {
	if b := g.fill(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

func (g *ggufReader) skip(k uint64) {
	if g.err != nil {
		return
	}
	if k > uint64(g.max-g.n) {
		g.err = errGGUFOver
		return
	}
	d, err := g.r.Discard(int(k))
	g.n += int64(d)
	if err != nil {
		g.err = err
	}
}

func (g *ggufReader) bytes(k uint64) []byte {
	if g.err != nil {
		return nil
	}
	if k > uint64(g.max-g.n) {
		g.err = errGGUFOver
		return nil
	}
	b := make([]byte, k)
	if _, err := io.ReadFull(g.r, b); err != nil {
		g.err = err
		return nil
	}
	g.n += int64(k)
	return b
}

// skipValue goes past a value of type t; false for a type the format does not have (or arrays nested too deep).
func (g *ggufReader) skipValue(t uint32, depth int, l GGUFLimits) bool {
	if sz, ok := ggufSizes[t]; ok {
		g.skip(sz)
		return true
	}
	switch t {
	case ggufString:
		if n := g.u64(); g.err == nil {
			g.skip(n)
		}
		return true
	case ggufArray:
		if depth >= 3 {
			return false
		}
		et, n := g.u32(), g.u64()
		if g.err != nil {
			return true
		}
		if n > l.MaxArray {
			g.err = errGGUFOver
			return true
		}
		if sz, ok := ggufSizes[et]; ok {
			g.skip(n * sz) // n ≤ 2^24, sz ≤ 8: no overflow
			return true
		}
		for i := uint64(0); i < n && g.err == nil; i++ {
			if !g.skipValue(et, depth+1, l) {
				return false
			}
		}
		return true
	}
	return false
}

// ReadGGUFTemplates reads a GGUF file's header up to the end of its metadata, keeping only its chat templates: every
// other value is gone past (the vocabulary's strings one length at a time), nothing after the metadata is read.
func ReadGGUFTemplates(r io.Reader, l GGUFLimits) GGUFTemplates {
	g := &ggufReader{r: bufio.NewReaderSize(r, 64<<10), max: l.MaxBytes}
	out := GGUFTemplates{Templates: map[string]string{}}
	done := func() GGUFTemplates {
		out.Read = g.n
		switch {
		case errors.Is(g.err, errGGUFOver):
			out.TooBig = true
		case g.err != nil:
			out.Bad = true
		}
		return out
	}
	if m := g.fill(4); m == nil || string(m) != "GGUF" {
		out.Bad = true
		out.Read = g.n
		return out
	}
	if v := g.u32(); v != 2 && v != 3 { // 1 had 32-bit counts; a big-endian file reads as a huge number
		out.Bad = true
		out.Read = g.n
		return out
	}
	g.u64() // tensors: not read
	entries := g.u64()
	if g.err == nil && entries > l.MaxEntries {
		g.err = errGGUFOver
	}
	for i := uint64(0); i < entries && g.err == nil; i++ {
		klen := g.u64()
		if g.err != nil {
			break
		}
		if klen > l.MaxKey {
			g.err = io.ErrUnexpectedEOF // not a key: the file is not what it says
			break
		}
		key := string(g.bytes(klen))
		t := g.u32()
		if g.err != nil {
			break
		}
		if t == ggufString && (key == "tokenizer.chat_template" || strings.HasPrefix(key, "tokenizer.chat_template.")) {
			n := g.u64()
			if g.err != nil {
				break
			}
			if n > l.MaxTemplate {
				out.TooBig = true
				g.skip(n)
				continue
			}
			if b := g.bytes(n); b != nil {
				out.Templates[strings.TrimPrefix(strings.TrimPrefix(key, "tokenizer.chat_template"), ".")] = string(b)
			}
			continue
		}
		if !g.skipValue(t, 0, l) {
			g.err = io.ErrUnexpectedEOF
		}
	}
	return done()
}
