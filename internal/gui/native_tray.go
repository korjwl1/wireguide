package gui

type nativeTrayItem struct {
	Title     string `json:"title,omitempty"`
	Action    string `json:"action,omitempty"`
	Enabled   bool   `json:"enabled"`
	Separator bool   `json:"separator,omitempty"`
}
