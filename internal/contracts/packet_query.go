package contracts

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"strconv"
	"unicode/utf8"
)

// PacketQueryCell is the closed primitive wire representation shared by native
// packet-query delivery and browser/MCP presentation. Domain values stay pure.
type PacketQueryCell struct {
	Text   *string `json:"text,omitempty"`
	Number *uint32 `json:"number,omitempty"`
}

func (c PacketQueryCell) MarshalJSON() ([]byte, error) {
	if c.Text != nil {
		if c.Number != nil || len(*c.Text) > 128 || !utf8.ValidString(*c.Text) {
			return nil, ErrInvestigationWire
		}
		return json.Marshal(*c.Text)
	}
	if c.Number != nil {
		return strconv.AppendUint(nil, uint64(*c.Number), 10), nil
	}
	return []byte("null"), nil
}

func (c *PacketQueryCell) UnmarshalJSON(raw []byte) error {
	*c = PacketQueryCell{}
	b := bytes.TrimSpace(raw)
	if len(b) == 0 || len(b) > 6*128+2 || !jsontext.Value(b).IsValid() {
		return ErrInvestigationWire
	}
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	if b[0] == '"' {
		var text string
		if json.Unmarshal(b, &text) != nil || len(text) > 128 {
			return ErrInvestigationWire
		}
		c.Text = &text
		return nil
	}
	for _, char := range b {
		if char < '0' || char > '9' {
			return ErrInvestigationWire
		}
	}
	number, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil {
		return ErrInvestigationWire
	}
	n := uint32(number)
	c.Number = &n
	return nil
}

// PacketQueryPage carries no authority or view lifetime. The authenticated
// source and enclosing query response provide those independently.
type PacketQueryPage struct {
	CaptureMode        string              `json:"capture_mode"`
	Fields             []string            `json:"fields"`
	Rows               [][]PacketQueryCell `json:"rows"`
	ScannedBytes       int64               `json:"scanned_bytes"`
	ScannedPackets     uint32              `json:"scanned_packets"`
	RowLimitReached    bool                `json:"row_limit_reached"`
	ScanLimitReached   bool                `json:"scan_limit_reached"`
	OutputLimitReached bool                `json:"output_limit_reached"`
}
