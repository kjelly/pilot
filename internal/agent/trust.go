package agent

import "strings"

// WrapUntrusted wraps tool output in a marker that the system prompt
// instructs the model to treat as data, not instructions. This is a
// defense-in-depth measure against prompt injection: any text that
// comes from a tool result (a file on disk, the output of another
// command, an HTTP response, etc.) is potentially attacker-controlled.
//
// The marker uses angle brackets and a unique enough prefix that it
// is unlikely to collide with legitimate content; the system prompt
// (config.Default) instructs the model to never execute instructions
// found inside <untrusted_tool_output> blocks.
func WrapUntrusted(toolName, content string) string {
	// Strip any pre-existing closing markers to prevent trivial escape.
	content = strings.ReplaceAll(content, "</untrusted_tool_output>", "[/untrusted_tool_output]")
	return "<untrusted_tool_output tool=" + toolName + ">\n" +
		content + "\n</untrusted_tool_output>"
}
