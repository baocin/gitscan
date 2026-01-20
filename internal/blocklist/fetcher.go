package blocklist

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Fetcher handles HTTP fetching of blocklist data
type Fetcher struct {
	client  *http.Client
	timeout time.Duration
}

// NewFetcher creates a new blocklist fetcher
func NewFetcher(timeout time.Duration) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		timeout: timeout,
	}
}

// FetchResult contains the result of a fetch operation
type FetchResult struct {
	Source   SourceType
	Data     string
	Entries  []Entry
	Error    error
	Duration time.Duration
}

// Fetch downloads and parses a blocklist from a source
func (f *Fetcher) Fetch(ctx context.Context, source Source) FetchResult {
	start := time.Now()
	result := FetchResult{
		Source: source.Type,
	}

	// Download data
	data, err := f.download(ctx, source.URL)
	if err != nil {
		result.Error = fmt.Errorf("download failed: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Data = data

	// Parse data
	entries, err := ParseBlocklist(data, source.Format, source.Type)
	if err != nil {
		result.Error = fmt.Errorf("parse failed: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Entries = entries
	result.Duration = time.Since(start)

	log.Printf("[blocklist] Fetched %s: %d entries in %v", source.Name, len(entries), result.Duration)
	return result
}

// download fetches data from a URL with context support
func (f *Fetcher) download(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	// Set User-Agent to identify ourselves
	req.Header.Set("User-Agent", "gitvet-blocklist/1.0 (https://git.vet)")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Read response body (limit to 50MB to prevent abuse)
	limitedReader := io.LimitReader(resp.Body, 50*1024*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// FetchAll fetches all sources concurrently
func (f *Fetcher) FetchAll(ctx context.Context, sources []Source) map[SourceType]FetchResult {
	results := make(map[SourceType]FetchResult)
	resultChan := make(chan FetchResult, len(sources))

	// Launch concurrent fetches
	for _, source := range sources {
		go func(s Source) {
			resultChan <- f.Fetch(ctx, s)
		}(source)
	}

	// Collect results
	for i := 0; i < len(sources); i++ {
		result := <-resultChan
		results[result.Source] = result
	}

	return results
}

// FetchWithRetry fetches with exponential backoff retry
func (f *Fetcher) FetchWithRetry(ctx context.Context, source Source, maxRetries int) FetchResult {
	var result FetchResult
	backoff := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		result = f.Fetch(ctx, source)
		if result.Error == nil {
			return result
		}

		// Don't retry on last attempt
		if attempt == maxRetries {
			break
		}

		log.Printf("[blocklist] Fetch failed for %s (attempt %d/%d): %v, retrying in %v",
			source.Name, attempt+1, maxRetries+1, result.Error, backoff)

		// Wait with exponential backoff
		select {
		case <-time.After(backoff):
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result
		}
	}

	return result
}
