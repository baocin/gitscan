package githttp

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// PktLineReader reads git pkt-line formatted data
type PktLineReader struct {
	r *bufio.Reader
}

// NewPktLineReader creates a new pkt-line reader
func NewPktLineReader(r io.Reader) *PktLineReader {
	return &PktLineReader{r: bufio.NewReader(r)}
}

// ReadPacket reads a single pkt-line packet
// Returns the data without the length prefix
// Returns io.EOF for flush packets (0000)
func (p *PktLineReader) ReadPacket() ([]byte, error) {
	// Read 4-byte hex length
	lenBytes := make([]byte, 4)
	if _, err := io.ReadFull(p.r, lenBytes); err != nil {
		return nil, err
	}

	length, err := strconv.ParseInt(string(lenBytes), 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid pkt-line length: %s", string(lenBytes))
	}

	// Flush packet
	if length == 0 {
		return nil, io.EOF
	}

	// Length includes the 4 length bytes
	dataLen := int(length) - 4
	if dataLen <= 0 {
		return []byte{}, nil
	}

	data := make([]byte, dataLen)
	if _, err := io.ReadFull(p.r, data); err != nil {
		return nil, err
	}

	return data, nil
}

// PktLineWriter writes git pkt-line formatted data
type PktLineWriter struct {
	w io.Writer
}

// NewPktLineWriter creates a new pkt-line writer
func NewPktLineWriter(w io.Writer) *PktLineWriter {
	return &PktLineWriter{w: w}
}

// WritePacket writes a pkt-line packet
func (p *PktLineWriter) WritePacket(data []byte) error {
	length := len(data) + 4
	if length > 65520 {
		return fmt.Errorf("packet too large: %d bytes", len(data))
	}
	_, err := fmt.Fprintf(p.w, "%04x%s", length, data)
	return err
}

// WriteString writes a string as a pkt-line packet
func (p *PktLineWriter) WriteString(s string) error {
	return p.WritePacket([]byte(s))
}

// WriteFlush writes a flush packet (0000)
func (p *PktLineWriter) WriteFlush() error {
	_, err := p.w.Write([]byte("0000"))
	return err
}

// WriteDelim writes a delimiter packet (0001)
func (p *PktLineWriter) WriteDelim() error {
	_, err := p.w.Write([]byte("0001"))
	return err
}

// GitRequest represents a parsed git HTTP request
type GitRequest struct {
	Service     string            // git-upload-pack, git-receive-pack
	RepoPath    string            // owner/repo
	Mode        string            // scan, clone, json, plain
	Host        string            // Request host
	Capabilities []string
	Wants       []string          // Requested object IDs
	Haves       []string          // Object IDs client has
	Done        bool
}

// ParseRepoPath parses a git repository path from the URL
// Supports formats:
//   /owner/repo.git/info/refs
//   /owner/repo/info/refs
//   /mode/owner/repo.git/info/refs
func ParseRepoPath(urlPath string) (mode, repoPath string, err error) {
	// Remove leading slash
	path := strings.TrimPrefix(urlPath, "/")

	// Remove .git suffix and git endpoints
	path = strings.TrimSuffix(path, ".git/info/refs")
	path = strings.TrimSuffix(path, "/info/refs")
	path = strings.TrimSuffix(path, ".git/git-upload-pack")
	path = strings.TrimSuffix(path, "/git-upload-pack")
	path = strings.TrimSuffix(path, ".git/git-receive-pack")
	path = strings.TrimSuffix(path, "/git-receive-pack")
	path = strings.TrimSuffix(path, ".git")

	parts := strings.Split(path, "/")

	// Check for mode prefix
	validModes := map[string]bool{
		"scan":  true,
		"clone": true,
		"json":  true,
		"plain": true,
	}

	if len(parts) >= 3 && validModes[parts[0]] {
		mode = parts[0]
		repoPath = strings.Join(parts[1:], "/")
	} else if len(parts) >= 2 {
		mode = "scan" // Default mode
		repoPath = strings.Join(parts, "/")
	} else {
		return "", "", fmt.Errorf("invalid repository path: %s", urlPath)
	}

	// Validate repo path format (owner/repo or owner/repo/...)
	repoParts := strings.Split(repoPath, "/")
	if len(repoParts) < 2 {
		return "", "", fmt.Errorf("invalid repository path: need owner/repo format")
	}

	return mode, repoPath, nil
}

// ParseGitRequest parses the request body for git-upload-pack
func ParseGitRequest(r io.Reader) (*GitRequest, error) {
	req := &GitRequest{}
	reader := NewPktLineReader(r)

	for {
		data, err := reader.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		line := strings.TrimSpace(string(data))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "want ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				req.Wants = append(req.Wants, parts[1])
			}
			// Parse capabilities from first want line
			if len(req.Capabilities) == 0 && len(parts) > 2 {
				req.Capabilities = parts[2:]
			}
		} else if strings.HasPrefix(line, "have ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				req.Haves = append(req.Haves, parts[1])
			}
		} else if line == "done" {
			req.Done = true
		}
	}

	return req, nil
}

// GitSmartResponse represents capabilities for git smart HTTP
type GitSmartResponse struct {
	Service      string
	Capabilities []string
	Refs         map[string]string // ref name -> object ID
	Head         string            // HEAD ref name
}

// WriteInfoRefs writes an info/refs response
func WriteInfoRefs(w io.Writer, service string) error {
	pkt := NewPktLineWriter(w)

	// Write service announcement
	if err := pkt.WriteString(fmt.Sprintf("# service=%s\n", service)); err != nil {
		return err
	}
	if err := pkt.WriteFlush(); err != nil {
		return err
	}

	return nil
}
