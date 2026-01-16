package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

const (
	defaultDomainSuffix = "mx-sink.wezfurlong.org"
	defaultTarget       = "127.0.0.1:2025"
	defaultDuration     = 60
	defaultBodySize     = 1024
	defaultBatchSize    = 1
)

var defaultDomains = []string{"aol.com", "gmail.com", "hotmail.com", "yahoo.com"}

// Config holds all configuration options
type Config struct {
	DomainSuffix        string
	Target              string
	Concurrency         int
	Duration            int
	MessageCount        int
	StartTLS            bool
	BodyFile            string
	BodyFileContent     string
	Domains             []string
	DomainWeights       []float64
	WeightedDistrib     []int
	ThrottleRate        float64
	Headers             []string
	BodySize            int
	BodySizeContent     string
	HTTP                bool
	HTTPDeferSpool      bool
	HTTPDeferGeneration bool
	HTTPBatchSize       int
	KeepGoing           bool
	APIKey              string
}

// InjectClient handles HTTP injection
type InjectClient struct {
	url       string
	client    *http.Client
	batchSize int
	apiKey    string
}

// EmailAddress represents an email address with localpart and domain
type EmailAddress struct {
	Localpart string `json:"localpart"`
	Domain    string `json:"domain"`
}

// SubmissionOptions represents the options for HTTP submission
type SubmissionOptions struct {
	Sender     EmailAddress      `json:"sender"`
	Recipients []EmailAddress    `json:"recipients"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Stats tracks sending statistics
type Stats struct {
	sent      atomic.Uint64
	failed    atomic.Uint64
	latencies []time.Duration
	mu        sync.Mutex
}

func (s *Stats) recordLatency(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latencies = append(s.latencies, d)
}

func (s *Stats) getLatencies() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]time.Duration, len(s.latencies))
	copy(result, s.latencies)
	return result
}

func main() {
	config := parseFlags()

	if err := config.loadBodyFile(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading body file: %v\n", err)
		os.Exit(1)
	}

	config.computeDomainWeights()

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, stopping...")
		cancel()
	}()

	if err := run(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.DomainSuffix, "domain-suffix", defaultDomainSuffix,
		"All generated mail will have this domain appended")
	flag.StringVar(&cfg.Target, "target", defaultTarget,
		"The target host to which mail will be submitted")
	flag.IntVar(&cfg.Concurrency, "concurrency", 0,
		"The number of connections to open to target (0 = auto)")
	flag.IntVar(&cfg.Duration, "duration", defaultDuration,
		"How many seconds to generate for")
	flag.IntVar(&cfg.MessageCount, "message-count", 0,
		"Generate exactly this many messages instead of running for duration")
	flag.BoolVar(&cfg.StartTLS, "starttls", false,
		"Whether to use STARTTLS for submission")
	flag.StringVar(&cfg.BodyFile, "body-file", "",
		"Take the message contents from the specified file")
	flag.Float64Var(&cfg.ThrottleRate, "throttle", 0,
		"Limit the sending rate to the specified rate (msgs/sec, 0 = unlimited)")
	flag.IntVar(&cfg.BodySize, "body-size", defaultBodySize,
		"When generating the body, use at least this many bytes")
	flag.BoolVar(&cfg.HTTP, "http", false,
		"Use http injection API instead of SMTP")
	flag.BoolVar(&cfg.HTTPDeferSpool, "http-defer-spool", false,
		"When using http injection, enable deferred_spool")
	flag.BoolVar(&cfg.HTTPDeferGeneration, "http-defer-generation", false,
		"When using http injection, enable deferred_generation")
	flag.IntVar(&cfg.HTTPBatchSize, "http-batch-size", defaultBatchSize,
		"When using http injection, how many recipients to generate in a single request")
	flag.BoolVar(&cfg.KeepGoing, "keep-going", false,
		"Continue sending even if errors are returned by the target")
	flag.StringVar(&cfg.APIKey, "api-key", "",
		"API key for HTTP submission (X-API-Key header)")

	// Custom flags for domains and headers
	var domainsFlag stringSliceFlag
	var headersFlag stringSliceFlag
	flag.Var(&domainsFlag, "domain", "Domain to use (can be specified multiple times)")
	flag.Var(&headersFlag, "header", "Custom header to add (can be specified multiple times)")

	flag.Parse()

	cfg.Domains = domainsFlag
	cfg.Headers = headersFlag

	if cfg.Concurrency == 0 {
		cfg.Concurrency = 10 // Default concurrency
	}

	return cfg
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (cfg *Config) loadBodyFile() error {
	if cfg.BodyFile != "" {
		data, err := os.ReadFile(cfg.BodyFile)
		if err != nil {
			return err
		}
		// Canonicalize line endings
		content := string(data)
		content = strings.ReplaceAll(content, "\r\n", "\n")
		content = strings.ReplaceAll(content, "\n", "\r\n")
		cfg.BodyFileContent = content
	} else {
		cfg.BodySizeContent = cfg.generateMessageText()
	}
	return nil
}

func (cfg *Config) computeDomainWeights() {
	var domains []string
	var weights []float64

	if len(cfg.Domains) == 0 {
		domains = defaultDomains
		weights = make([]float64, len(defaultDomains))
		for i := range weights {
			weights[i] = 1.0
		}
	} else {
		for _, domain := range cfg.Domains {
			parts := strings.Split(domain, ":")
			if len(parts) == 2 {
				domains = append(domains, parts[0])
				var weight float64
				fmt.Sscanf(parts[1], "%f", &weight)
				weights = append(weights, weight)
			} else {
				domains = append(domains, domain)
				weights = append(weights, 1.0)
			}
		}
	}

	cfg.Domains = domains
	cfg.DomainWeights = weights

	// Create weighted distribution lookup table
	totalWeight := 0.0
	for _, w := range weights {
		totalWeight += w
	}

	// Create a lookup table with 1000 entries for efficient sampling
	cfg.WeightedDistrib = make([]int, 1000)
	idx := 0
	for i, weight := range weights {
		count := int((weight / totalWeight) * 1000)
		for j := 0; j < count && idx < 1000; j++ {
			cfg.WeightedDistrib[idx] = i
			idx++
		}
	}
	// Fill remaining slots with first domain
	for idx < 1000 {
		cfg.WeightedDistrib[idx] = 0
		idx++
	}
}

func (cfg *Config) pickDomain() string {
	idx := rand.Intn(len(cfg.WeightedDistrib))
	domainIdx := cfg.WeightedDistrib[idx]
	domain := cfg.Domains[domainIdx]

	if cfg.DomainSuffix == "" {
		return domain
	}
	return fmt.Sprintf("%s.%s", domain, cfg.DomainSuffix)
}

func (cfg *Config) generateSender() string {
	return fmt.Sprintf("noreply@%s", cfg.pickDomain())
}

func (cfg *Config) generateRecipient() string {
	number := rand.Uint64()
	domain := cfg.pickDomain()
	return fmt.Sprintf("user-%d@%s", number, domain)
}

func (cfg *Config) generateMessageText() string {
	// Generate Lorem Ipsum-like text
	words := []string{
		"lorem", "ipsum", "dolor", "sit", "amet", "consectetur",
		"adipiscing", "elit", "sed", "do", "eiusmod", "tempor",
		"incididunt", "ut", "labore", "et", "dolore", "magna",
		"aliqua", "enim", "ad", "minim", "veniam", "quis",
		"nostrud", "exercitation", "ullamco", "laboris", "nisi",
		"aliquip", "ex", "ea", "commodo", "consequat",
	}

	var result strings.Builder
	lineLen := 0

	for result.Len() < cfg.BodySize {
		word := words[rand.Intn(len(words))]
		if lineLen+len(word)+1 > 78 {
			result.WriteString("\r\n")
			lineLen = 0
		}
		if lineLen > 0 {
			result.WriteString(" ")
			lineLen++
		}
		result.WriteString(word)
		lineLen += len(word)
	}
	result.WriteString("\r\n")

	return result.String()
}

func (cfg *Config) generateBody(sender, recip string) string {
	if cfg.BodyFileContent != "" {
		return cfg.BodyFileContent
	}

	now := time.Now()
	datestamp := now.Format(time.RFC1123Z)
	id := uuid.New().String()

	var msg strings.Builder
	fmt.Fprintf(&msg, "From: <%s>\r\n", sender)
	fmt.Fprintf(&msg, "To: <%s>\r\n", recip)
	fmt.Fprintf(&msg, "Subject: test %s\r\n", datestamp)
	fmt.Fprintf(&msg, "Message-Id: %s\r\n", id)
	msg.WriteString("X-Mailer: Email traffic-gen\r\n")

	for _, header := range cfg.Headers {
		if !strings.HasSuffix(header, "\r\n") {
			msg.WriteString(header)
			msg.WriteString("\r\n")
		} else {
			msg.WriteString(header)
		}
	}

	msg.WriteString("\r\n")
	msg.WriteString(cfg.BodySizeContent)

	return msg.String()
}

func (cfg *Config) generateMessage() (string, string, string) {
	sender := cfg.generateSender()
	recip := cfg.generateRecipient()
	body := cfg.generateBody(sender, recip)
	return sender, recip, body
}

func (cfg *Config) makeHTTPClient() *InjectClient {
	url := cfg.Target
	if url == "127.0.0.1:2025" {
		url = "http://127.0.0.1:80"
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	url = url + "/v1/submission"

	return &InjectClient{
		url:       url,
		client:    &http.Client{Timeout: 60 * time.Second},
		batchSize: cfg.HTTPBatchSize,
		apiKey:    cfg.APIKey,
	}
}

func (ic *InjectClient) sendMail(sender, recip, body string) error {
	// Parse sender email
	senderParts := strings.SplitN(sender, "@", 2)
	if len(senderParts) != 2 {
		return fmt.Errorf("invalid sender email: %s", sender)
	}

	// Parse recipient email
	recipParts := strings.SplitN(recip, "@", 2)
	if len(recipParts) != 2 {
		return fmt.Errorf("invalid recipient email: %s", recip)
	}

	// Build recipients array
	recipients := make([]EmailAddress, ic.batchSize)
	for i := 0; i < ic.batchSize; i++ {
		recipients[i] = EmailAddress{
			Localpart: recipParts[0],
			Domain:    recipParts[1],
		}
	}

	// Build options JSON
	options := SubmissionOptions{
		Sender: EmailAddress{
			Localpart: senderParts[0],
			Domain:    senderParts[1],
		},
		Recipients: recipients,
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add options part with proper Content-Disposition header
	optionsPart, err := writer.CreateFormFile("options", "options.json")
	if err != nil {
		return fmt.Errorf("failed to create options field: %w", err)
	}
	if _, err := optionsPart.Write(optionsJSON); err != nil {
		return fmt.Errorf("failed to write options: %w", err)
	}

	// Add rfc822 part with proper Content-Disposition header
	rfc822Part, err := writer.CreateFormFile("rfc822", "message.eml")
	if err != nil {
		return fmt.Errorf("failed to create rfc822 field: %w", err)
	}
	if _, err := rfc822Part.Write([]byte(body)); err != nil {
		return fmt.Errorf("failed to write rfc822: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", ic.url, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if ic.apiKey != "" {
		req.Header.Set("X-API-Key", ic.apiKey)
	}

	// Send request
	resp, err := ic.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("request status %d, failed to read response body: %w", resp.StatusCode, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (cfg *Config) sendViaSMTP(sender, recip, body string) error {
	conn, err := net.DialTimeout("tcp", cfg.Target, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, strings.Split(cfg.Target, ":")[0])
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if err := client.Hello(cfg.pickDomain()); err != nil {
		return fmt.Errorf("EHLO failed: %w", err)
	}

	if cfg.StartTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         strings.Split(cfg.Target, ":")[0],
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %w", err)
			}
		}
	}

	if err := client.Mail(sender); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err := client.Rcpt(recip); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	if _, err := wc.Write([]byte(body)); err != nil {
		wc.Close()
		return fmt.Errorf("failed to write body: %w", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close DATA: %w", err)
	}

	return client.Quit()
}

func run(ctx context.Context, cfg *Config) error {
	stats := &Stats{}
	start := time.Now()

	var limiter *rate.Limiter
	if cfg.ThrottleRate > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.ThrottleRate), int(cfg.ThrottleRate)+1)
	}

	var wg sync.WaitGroup
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	// Start worker goroutines
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(workerCtx, cfg, stats, limiter)
		}()
	}

	// Progress reporter
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastSent uint64
	lastUpdate := time.Now()

	// Determine when to stop
	var deadline <-chan time.Time
	if cfg.MessageCount == 0 {
		timer := time.NewTimer(time.Duration(cfg.Duration) * time.Second)
		defer timer.Stop()
		deadline = timer.C
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-deadline:
			fmt.Println("\nDeadline reached, stopping")
			break loop
		case <-ticker.C:
			now := time.Now()
			currentSent := stats.sent.Load()

			if cfg.MessageCount > 0 && currentSent >= uint64(cfg.MessageCount) {
				break loop
			}

			elapsed := now.Sub(lastUpdate)
			sent := currentSent - lastSent
			rate := float64(sent) / elapsed.Seconds()

			fmt.Printf("\r\033[Kcurrent rate: %s (sent=%s, clients=%d)",
				formatRate(rate),
				formatNumber(currentSent),
				cfg.Concurrency)

			lastSent = currentSent
			lastUpdate = now
		case <-done:
			fmt.Println("\nAll clients finished")
			break loop
		}
	}

	// Stop all workers
	workerCancel()
	wg.Wait()

	// Print final statistics
	elapsed := time.Since(start)
	totalSent := stats.sent.Load()
	totalFailed := stats.failed.Load()

	fmt.Printf("\nsent %s messages, failed %s over %v.\n",
		formatNumber(totalSent),
		formatNumber(totalFailed),
		elapsed)

	// Print latency statistics
	printLatencyStats(stats.getLatencies())

	// Print overall rate
	overallRate := float64(totalSent) / elapsed.Seconds()
	fmt.Printf("overall rate: %s\n", formatRate(overallRate))

	return nil
}

func worker(ctx context.Context, cfg *Config, stats *Stats, limiter *rate.Limiter) {
	var httpClient *InjectClient
	if cfg.HTTP {
		httpClient = cfg.makeHTTPClient()
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check message count limit
		if cfg.MessageCount > 0 {
			current := stats.sent.Load()
			if current >= uint64(cfg.MessageCount) {
				return
			}
		}

		// Apply rate limiting
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return
			}
		}

		sender, recip, body := cfg.generateMessage()
		start := time.Now()

		var err error
		if cfg.HTTP {
			err = httpClient.sendMail(sender, recip, body)
			if err == nil {
				stats.sent.Add(uint64(cfg.HTTPBatchSize))
			}
		} else {
			err = cfg.sendViaSMTP(sender, recip, body)
			if err == nil {
				stats.sent.Add(1)
			}
		}

		latency := time.Since(start)
		stats.recordLatency(latency)

		if err != nil {
			stats.failed.Add(1)
			if !cfg.KeepGoing {
				fmt.Fprintf(os.Stderr, "\nError sending mail: %v\n", err)
				return
			}
		}
	}
}

func formatNumber(n uint64) string {
	s := fmt.Sprintf("%d", n)
	var result strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result.WriteRune(',')
		}
		result.WriteRune(c)
	}
	return result.String()
}

func formatRate(rate float64) string {
	perSecond := rate
	perMinute := rate * 60
	perHour := perMinute * 60

	return fmt.Sprintf("%.0f msgs/s, %.0f msgs/minute, %.0f msgs/hour",
		perSecond, perMinute, perHour)
}

func printLatencyStats(latencies []time.Duration) {
	if len(latencies) == 0 {
		return
	}

	// Sort latencies for percentile calculation
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var sum time.Duration
	for _, l := range sorted {
		sum += l
	}
	avg := sum / time.Duration(len(sorted))

	percentile := func(p float64) time.Duration {
		idx := int(float64(len(sorted)-1) * p / 100.0)
		return sorted[idx]
	}

	fmt.Printf("transaction latency: avg=%v min=%v max=%v p50=%v p75=%v p90=%v p95=%v p99=%v p99.9=%v\n",
		avg,
		sorted[0],
		sorted[len(sorted)-1],
		percentile(50),
		percentile(75),
		percentile(90),
		percentile(95),
		percentile(99),
		percentile(99.9))
}
