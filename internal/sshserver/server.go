package sshserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/githttp"
)

// Server implements an SSH server for git operations
type Server struct {
	addr       string
	hostKey    ssh.Signer
	handler    *githttp.Handler
	db         *db.DB
	config     *ssh.ServerConfig
	listener   net.Listener
}

// Config holds SSH server configuration
type Config struct {
	ListenAddr  string // Address to listen on (e.g., ":22")
	HostKeyPath string // Path to host key file (generated if missing)
}

// DefaultConfig returns default SSH server configuration
func DefaultConfig() Config {
	return Config{
		ListenAddr:  ":22",
		HostKeyPath: "/var/lib/gitvet/ssh_host_key",
	}
}

// New creates a new SSH server
func New(config Config, handler *githttp.Handler, database *db.DB) (*Server, error) {
	// Load or generate host key
	hostKey, err := loadOrGenerateHostKey(config.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	// Create SSH server configuration
	sshConfig := &ssh.ServerConfig{
		// Allow all public keys (we log them but don't authenticate)
		// This is safe because we're just a read-only proxy
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fingerprint := ssh.FingerprintSHA256(key)
			log.Printf("[ssh] Public key authentication from %s (key: %s)", conn.RemoteAddr(), fingerprint)

			// Store fingerprint in permissions for later logging
			return &ssh.Permissions{
				Extensions: map[string]string{
					"key-fingerprint": fingerprint,
				},
			}, nil
		},
	}

	sshConfig.AddHostKey(hostKey)

	return &Server{
		addr:    config.ListenAddr,
		hostKey: hostKey,
		handler: handler,
		db:      database,
		config:  sshConfig,
	}, nil
}

// Listen starts the SSH server
func (s *Server) Listen() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.addr, err)
	}
	s.listener = listener

	log.Printf("SSH server listening on %s", s.addr)
	log.Printf("SSH host key fingerprint: %s", ssh.FingerprintSHA256(s.hostKey.PublicKey()))

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if listener was closed intentionally
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				log.Printf("[ssh] SSH server stopped")
				return nil
			}
			log.Printf("[ssh] Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// Close stops the SSH server
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// handleConnection handles a single SSH connection
func (s *Server) handleConnection(netConn net.Conn) {
	defer netConn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.config)
	if err != nil {
		log.Printf("[ssh] Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	// Get SSH key fingerprint from permissions
	fingerprint := ""
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions != nil {
		fingerprint = sshConn.Permissions.Extensions["key-fingerprint"]
	}

	log.Printf("[ssh] New SSH connection from %s (user: %s, key: %s)",
		sshConn.RemoteAddr(), sshConn.User(), fingerprint)

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		go s.handleChannel(sshConn, newChannel, fingerprint)
	}
}

// handleChannel handles a single SSH channel (session)
func (s *Server) handleChannel(conn *ssh.ServerConn, newChannel ssh.NewChannel, fingerprint string) {
	// Only accept session channels
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("[ssh] Failed to accept channel: %v", err)
		return
	}
	defer channel.Close()

	// Handle session requests (exec, shell, etc.)
	for req := range requests {
		switch req.Type {
		case "exec":
			// Parse the command
			command := string(req.Payload[4:]) // Skip length prefix
			log.Printf("[ssh] Exec request: %s", command)

			// Reply to the request
			if req.WantReply {
				req.Reply(true, nil)
			}

			// Handle git commands
			if err := s.handleGitCommand(conn, channel, command, fingerprint); err != nil {
				log.Printf("[ssh] Failed to handle git command: %v", err)
				fmt.Fprintf(channel.Stderr(), "Error: %v\n", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
			} else {
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			}

			return

		default:
			// Reject other request types
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// Git command pattern: git-upload-pack '/github.com/owner/repo'
var gitCommandPattern = regexp.MustCompile(`^git-upload-pack\s+'?/?([^']+?)'?$`)

// handleGitCommand processes git SSH commands
func (s *Server) handleGitCommand(conn *ssh.ServerConn, channel ssh.Channel, command string, fingerprint string) error {
	// Parse git command
	matches := gitCommandPattern.FindStringSubmatch(command)
	if matches == nil {
		return fmt.Errorf("unsupported command: %s (expected: git-upload-pack '/github.com/owner/repo')", command)
	}

	repoPath := strings.Trim(matches[1], "/ ")
	log.Printf("[ssh] Git upload-pack request for: %s (user: %s, key: %s)",
		repoPath, conn.User(), fingerprint)

	// Parse the repository path using githttp's parser
	parsed, err := githttp.ParseRepoPathFull("/" + repoPath)
	if err != nil {
		return fmt.Errorf("invalid repository path: %w", err)
	}

	log.Printf("[ssh] Parsed repo: %s/%s/%s (mode: %s)",
		parsed.Host, parsed.Owner, parsed.Repo, parsed.Mode)

	// Log this SSH scan request to database
	clientIP := conn.RemoteAddr().String()
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx] // Strip port
	}

	// Log SSH request BEFORE any processing
	log.Printf("[ssh] Logging request to database...")
	if err := s.db.LogRequest(&db.Request{
		IP:                clientIP,
		SSHKeyFingerprint: fingerprint,
		UserAgent:         fmt.Sprintf("git-ssh/%s", conn.User()),
		RepoURL:           parsed.FullPath,
		RequestMode:       parsed.Mode,
		RequestType:       "ssh_upload_pack",
		HTTPMethod:        "SSH",
		Success:           true,
		ResponseTimeMS:    0,
	}); err != nil {
		log.Printf("[ssh] Warning: Failed to log request: %v", err)
	}
	log.Printf("[ssh] Request logged successfully")

	// Create context for the scan
	ctx := context.Background()
	startTime := time.Now()

	// Read and parse client's git request (want/have lines) before replying
	// This is required by git protocol - client sends wants, server responds
	_, err = githttp.ParseGitRequest(channel)
	if err != nil {
		return fmt.Errorf("failed to parse git request: %w", err)
	}

	// Send git protocol header (NAK before sideband messages)
	pkt := githttp.NewPktLineWriter(channel)
	if err := pkt.WriteString("NAK\n"); err != nil {
		return fmt.Errorf("failed to write NAK: %w", err)
	}

	// Create sideband writer for streaming output through SSH
	useColors := parsed.Mode != "plain"
	sb := githttp.NewSidebandWriter(channel, useColors)

	// Determine if this is a private repo (SSH always allows private repos)
	// We'll treat all SSH requests as potentially private for now
	isPrivate := false // TODO: Detect based on repo metadata after fetch

	// Create user agent string for SSH
	userAgent := fmt.Sprintf("git-ssh/%s (fingerprint: %s)", conn.User(), fingerprint)

	// Perform the actual scan using the githttp handler
	// This will stream all output through the sideband writer
	s.handler.PerformScanSSH(ctx, sb, parsed, clientIP, userAgent, startTime, isPrivate, false)

	// Send empty packfile and flush to properly terminate git protocol
	sb.WriteEmptyPackfile()
	sb.Flush()

	log.Printf("[ssh] Completed scan for %s (user: %s, key: %s)",
		parsed.FullPath, conn.User(), fingerprint)

	return nil
}

// loadOrGenerateHostKey loads an existing host key or generates a new one
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	// Try to load existing key
	keyBytes, err := os.ReadFile(path)
	if err == nil {
		// Parse existing key
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key: %w", err)
		}
		log.Printf("[ssh] Loaded existing host key from %s", path)
		return signer, nil
	}

	// Key doesn't exist, generate new one
	log.Printf("[ssh] Generating new SSH host key at %s", path)

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to file
	keyFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create host key file: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("failed to write host key: %w", err)
	}

	// Convert to SSH signer
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	log.Printf("[ssh] Generated new host key with fingerprint: %s", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}
