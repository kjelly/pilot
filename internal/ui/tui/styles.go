// Package tui: lipgloss styles and palette.
package tui

import "github.com/charmbracelet/lipgloss"

// Palette holds the colors for a particular theme. The values are
// ANSI names that lipgloss understands.
type Palette struct {
	Background   lipgloss.Color // terminal background, used for clearing
	Foreground   lipgloss.Color // default text
	Muted        lipgloss.Color // secondary text (rationale, metadata)
	Accent       lipgloss.Color // headings, focus
	Border       lipgloss.Color // pane borders
	UserMsg      lipgloss.Color // user messages in chat
	AssistantMsg lipgloss.Color // assistant messages
	ToolCall     lipgloss.Color // tool call labels
	ToolResult   lipgloss.Color // tool result text
	ToolError    lipgloss.Color // error results
	Thinking     lipgloss.Color // model "thinking" output
	Low          lipgloss.Color // low risk
	Medium       lipgloss.Color // medium risk
	High         lipgloss.Color // high risk
	Selected     lipgloss.Color // selected option in prompts
	Pending      lipgloss.Color // status "pending" pill
	Applied      lipgloss.Color // status "applied" pill
	Rejected     lipgloss.Color // status "rejected" pill
}

var darkPalette = Palette{
	Background:   lipgloss.Color("#1e1e2e"),
	Foreground:   lipgloss.Color("#cdd6f4"),
	Muted:        lipgloss.Color("#9399b2"),
	Accent:       lipgloss.Color("#cba6f7"),
	Border:       lipgloss.Color("#45475a"),
	UserMsg:      lipgloss.Color("#89b4fa"),
	AssistantMsg: lipgloss.Color("#cdd6f4"),
	ToolCall:     lipgloss.Color("#f9e2af"),
	ToolResult:   lipgloss.Color("#a6e3a1"),
	ToolError:    lipgloss.Color("#f38ba8"),
	Thinking:     lipgloss.Color("#7f849c"),
	Low:          lipgloss.Color("#a6e3a1"),
	Medium:       lipgloss.Color("#f9e2af"),
	High:         lipgloss.Color("#f38ba8"),
	Selected:     lipgloss.Color("#cba6f7"),
	Pending:      lipgloss.Color("#f9e2af"),
	Applied:      lipgloss.Color("#a6e3a1"),
	Rejected:     lipgloss.Color("#9399b2"),
}

var lightPalette = Palette{
	Background:   lipgloss.Color("#eff1f5"),
	Foreground:   lipgloss.Color("#4c4f69"),
	Muted:        lipgloss.Color("#8c8fa1"),
	Accent:       lipgloss.Color("#8839ef"),
	Border:       lipgloss.Color("#bcc0cc"),
	UserMsg:      lipgloss.Color("#1e66f5"),
	AssistantMsg: lipgloss.Color("#4c4f69"),
	ToolCall:     lipgloss.Color("#df8e1d"),
	ToolResult:   lipgloss.Color("#40a02b"),
	ToolError:    lipgloss.Color("#d20f39"),
	Thinking:     lipgloss.Color("#9ca0b0"),
	Low:          lipgloss.Color("#40a02b"),
	Medium:       lipgloss.Color("#df8e1d"),
	High:         lipgloss.Color("#d20f39"),
	Selected:     lipgloss.Color("#8839ef"),
	Pending:      lipgloss.Color("#df8e1d"),
	Applied:      lipgloss.Color("#40a02b"),
	Rejected:     lipgloss.Color("#9ca0b0"),
}

// Styles holds the lipgloss style objects used by the views.
type Styles struct {
	Palette Palette

	// Base frame
	Base lipgloss.Style

	// Panes
	ChatPane      lipgloss.Style
	ProposalPane  lipgloss.Style
	PaneTitle     lipgloss.Style
	PaneTitleChat lipgloss.Style

	// Status bar
	StatusBar  lipgloss.Style
	StatusItem lipgloss.Style

	// Modal
	Modal       lipgloss.Style
	ModalTitle  lipgloss.Style
	ModalOption lipgloss.Style
	ModalActive lipgloss.Style

	// Content
	UserBubble      lipgloss.Style
	AssistantBubble lipgloss.Style
	ToolBlock       lipgloss.Style
	ToolLabel       lipgloss.Style
	Thinking        lipgloss.Style
	Rationale       lipgloss.Style
	Diff            lipgloss.Style
	Risk            func(level string) lipgloss.Style

	// Status pills
	PillPending  lipgloss.Style
	PillApplied  lipgloss.Style
	PillRejected lipgloss.Style
}

func NewStyles(dark bool) *Styles {
	p := darkPalette
	if !dark {
		p = lightPalette
	}
	s := &Styles{Palette: p}
	s.Base = lipgloss.NewStyle().Foreground(p.Foreground).Background(p.Background)

	s.ChatPane = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(p.Border).
		Padding(0, 1)
	s.ProposalPane = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(p.Border).
		Padding(0, 1)
	s.PaneTitle = lipgloss.NewStyle().Bold(true).Foreground(p.Accent)
	s.PaneTitleChat = lipgloss.NewStyle().Bold(true).Foreground(p.UserMsg)

	s.StatusBar = lipgloss.NewStyle().
		Foreground(p.Muted).
		Background(p.Background).
		Padding(0, 1)
	s.StatusItem = lipgloss.NewStyle().Foreground(p.Foreground)

	s.Modal = lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(p.Accent).
		Padding(1, 2)
	s.ModalTitle = lipgloss.NewStyle().Bold(true).Foreground(p.Accent)
	s.ModalOption = lipgloss.NewStyle().Foreground(p.Muted)
	s.ModalActive = lipgloss.NewStyle().Bold(true).Foreground(p.Selected)

	s.UserBubble = lipgloss.NewStyle().Foreground(p.UserMsg).Bold(true)
	s.AssistantBubble = lipgloss.NewStyle().Foreground(p.AssistantMsg)
	s.ToolBlock = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(p.Border).
		Padding(0, 1).
		MarginTop(1).
		MarginBottom(1)
	s.ToolLabel = lipgloss.NewStyle().Bold(true).Foreground(p.ToolCall)
	s.Thinking = lipgloss.NewStyle().Foreground(p.Thinking).Italic(true)
	s.Rationale = lipgloss.NewStyle().Foreground(p.Foreground)
	s.Diff = lipgloss.NewStyle().Foreground(p.Muted)
	s.Risk = func(level string) lipgloss.Style {
		switch level {
		case "low":
			return lipgloss.NewStyle().Foreground(p.Low).Bold(true)
		case "medium":
			return lipgloss.NewStyle().Foreground(p.Medium).Bold(true)
		case "high":
			return lipgloss.NewStyle().Foreground(p.High).Bold(true)
		}
		return lipgloss.NewStyle().Foreground(p.Muted)
	}

	s.PillPending = lipgloss.NewStyle().Foreground(p.Background).Background(p.Pending).Padding(0, 1)
	s.PillApplied = lipgloss.NewStyle().Foreground(p.Background).Background(p.Applied).Padding(0, 1)
	s.PillRejected = lipgloss.NewStyle().Foreground(p.Background).Background(p.Rejected).Padding(0, 1)
	return s
}
