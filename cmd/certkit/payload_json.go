package main

// payloadJSON is the JSON output structure for commands that emit transformed
// payload data (`bundle` and `convert`).
type payloadJSON struct {
	Data     string `json:"data,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	File     string `json:"file,omitempty"`
	Format   string `json:"format,omitempty"`
	Size     int    `json:"size,omitempty"`
}
