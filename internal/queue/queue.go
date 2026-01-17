package queue

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Priority levels for queue
type Priority int

const (
	PriorityLow    Priority = 0 // Free tier, public repos
	PriorityNormal Priority = 1 // Free tier, private repos (with delay)
	PriorityHigh   Priority = 2 // Paid tier
)

// Job represents a scan job in the queue
type Job struct {
	ID        string
	RepoPath  string
	Priority  Priority
	IsPrivate bool
	IsPaid    bool
	ClientIP  string
	CreatedAt time.Time
	StartedAt time.Time

	// Cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Result channel
	Done   chan struct{}
	Error  error
	Result interface{}
}

// Manager manages the job queue with priority handling
type Manager struct {
	mu sync.RWMutex

	// Separate queues by priority
	queues map[Priority]chan *Job

	// Active jobs by ID
	active map[string]*Job

	// Configuration
	maxConcurrentPublic  int
	maxConcurrentPrivate int
	maxQueueSize         int

	// Semaphores for concurrency control
	publicSem  chan struct{}
	privateSem chan struct{}

	// Stats
	stats Stats
}

// Stats contains queue statistics
type Stats struct {
	PublicQueued   int
	PrivateQueued  int
	PublicActive   int
	PrivateActive  int
	TotalProcessed int64
	TotalCancelled int64
}

// Config holds queue configuration
type Config struct {
	MaxConcurrentPublic  int
	MaxConcurrentPrivate int
	MaxQueueSize         int
}

// DefaultConfig returns default queue configuration
func DefaultConfig() Config {
	return Config{
		MaxConcurrentPublic:  10, // More capacity for public repos
		MaxConcurrentPrivate: 3,  // Limited capacity for private repos
		MaxQueueSize:         100,
	}
}

// NewManager creates a new queue manager
func NewManager(config Config) *Manager {
	m := &Manager{
		queues:               make(map[Priority]chan *Job),
		active:               make(map[string]*Job),
		maxConcurrentPublic:  config.MaxConcurrentPublic,
		maxConcurrentPrivate: config.MaxConcurrentPrivate,
		maxQueueSize:         config.MaxQueueSize,
		publicSem:            make(chan struct{}, config.MaxConcurrentPublic),
		privateSem:           make(chan struct{}, config.MaxConcurrentPrivate),
	}

	// Initialize priority queues
	m.queues[PriorityLow] = make(chan *Job, config.MaxQueueSize)
	m.queues[PriorityNormal] = make(chan *Job, config.MaxQueueSize)
	m.queues[PriorityHigh] = make(chan *Job, config.MaxQueueSize)

	return m
}

// Submit adds a job to the queue
func (m *Manager) Submit(ctx context.Context, repoPath string, isPrivate, isPaid bool, clientIP string) (*Job, error) {
	jobCtx, cancel := context.WithCancel(ctx)

	priority := PriorityLow
	if isPaid {
		priority = PriorityHigh
	} else if isPrivate {
		priority = PriorityNormal
	}

	job := &Job{
		ID:        generateJobID(),
		RepoPath:  repoPath,
		Priority:  priority,
		IsPrivate: isPrivate,
		IsPaid:    isPaid,
		ClientIP:  clientIP,
		CreatedAt: time.Now(),
		ctx:       jobCtx,
		cancel:    cancel,
		Done:      make(chan struct{}),
	}

	m.mu.Lock()
	m.active[job.ID] = job
	m.mu.Unlock()

	// Try to add to appropriate queue
	select {
	case m.queues[priority] <- job:
		return job, nil
	default:
		// Queue full
		cancel()
		m.mu.Lock()
		delete(m.active, job.ID)
		m.mu.Unlock()
		return nil, ErrQueueFull
	}
}

// Cancel cancels a job by ID
func (m *Manager) Cancel(jobID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if job, ok := m.active[jobID]; ok {
		job.cancel()
		m.stats.TotalCancelled++
		return true
	}
	return false
}

// GetStats returns current queue statistics
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	stats.PublicQueued = len(m.queues[PriorityLow])
	stats.PrivateQueued = len(m.queues[PriorityNormal]) + len(m.queues[PriorityHigh])
	stats.PublicActive = m.maxConcurrentPublic - len(m.publicSem)
	stats.PrivateActive = m.maxConcurrentPrivate - len(m.privateSem)

	return stats
}

// AcquireSlot acquires a processing slot (blocks until available)
func (m *Manager) AcquireSlot(isPrivate bool) {
	if isPrivate {
		m.privateSem <- struct{}{}
	} else {
		m.publicSem <- struct{}{}
	}
}

// ReleaseSlot releases a processing slot
func (m *Manager) ReleaseSlot(isPrivate bool) {
	if isPrivate {
		<-m.privateSem
	} else {
		<-m.publicSem
	}
}

// MarkComplete marks a job as complete
func (m *Manager) MarkComplete(jobID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if job, ok := m.active[jobID]; ok {
		close(job.Done)
		delete(m.active, jobID)
		m.stats.TotalProcessed++
	}
}

// IsClientDisconnected checks if the client has disconnected
func (m *Manager) IsClientDisconnected(job *Job) bool {
	select {
	case <-job.ctx.Done():
		return true
	default:
		return false
	}
}

// WaitForSlot waits for a processing slot, checking for cancellation
func (m *Manager) WaitForSlot(ctx context.Context, isPrivate bool) error {
	sem := m.publicSem
	if isPrivate {
		sem = m.privateSem
	}

	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Error types
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrQueueFull      Error = "queue is full, please try again later"
	ErrClientCanceled Error = "client disconnected"
)

// generateJobID generates a unique job ID
func generateJobID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
