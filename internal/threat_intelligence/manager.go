package threat_intelligence

import (
	"sync"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

type Manager struct {
	config    *config.ThreatIntelligenceConfig
	enricher  *Enricher
	db        *database.SQLiteDB
	queue     chan EnrichmentJob
	workers   int
	stopChan  chan bool
	wg        sync.WaitGroup
	mu        sync.RWMutex
}

type EnrichmentJob struct {
	AppID    string
	SourceIP string
	Retry    int
	MaxRetry int
}

func NewManager(cfg *config.ThreatIntelligenceConfig, db *database.SQLiteDB) *Manager {
	workers := cfg.EnrichmentWorkers
	if workers <= 0 {
		workers = 3
	}

	return &Manager{
		config:   cfg,
		enricher: NewEnricher(cfg, db),
		db:       db,
		queue:    make(chan EnrichmentJob, 1000), // Buffer for 1000 jobs
		workers:  workers,
		stopChan: make(chan bool),
	}
}

// Start starts the enrichment worker goroutines
func (m *Manager) Start() {
	if !m.config.Enabled {
		logging.Info("[THREAT_INTEL] Threat Intelligence disabled in config")
		return
	}

	logging.Info("[THREAT_INTEL] Starting %d enrichment workers", m.workers)

	for i := 0; i < m.workers; i++ {
		m.wg.Add(1)
		go m.worker(i)
	}
}

// Stop gracefully shuts down enrichment workers
func (m *Manager) Stop() {
	logging.Info("[THREAT_INTEL] Stopping enrichment workers")
	close(m.stopChan)
	m.wg.Wait()
	close(m.queue)
	logging.Info("[THREAT_INTEL] Enrichment workers stopped")
}

// EnqueueEnrichment adds an IP to the enrichment queue
func (m *Manager) EnqueueEnrichment(appID, sourceIP string) {
	if !m.config.Enabled {
		return
	}

	// Check if already cached to avoid queue buildup
	cached, err := m.db.IsThreatIntelligenceCached(appID, sourceIP)
	if err == nil && cached {
		return // Already cached, no need to enqueue
	}

	job := EnrichmentJob{
		AppID:    appID,
		SourceIP: sourceIP,
		Retry:    0,
		MaxRetry: 3,
	}

	// Non-blocking send (queue might be full, but that's okay - we'll skip)
	select {
	case m.queue <- job:
		logging.Info("[THREAT_INTEL] Enqueued enrichment job for IP: %s (app_id: %s)", sourceIP, appID)
	default:
		logging.Info("[THREAT_INTEL] Queue full, skipping enrichment for IP: %s", sourceIP)
	}
}

// worker processes enrichment jobs from the queue
func (m *Manager) worker(id int) {
	defer m.wg.Done()
	logging.Info("[THREAT_INTEL] Worker %d started", id)

	for {
		select {
		case <-m.stopChan:
			logging.Info("[THREAT_INTEL] Worker %d stopping", id)
			return

		case job, ok := <-m.queue:
			if !ok {
				logging.Info("[THREAT_INTEL] Worker %d queue closed", id)
				return
			}

			m.processJob(job, id)
		}
	}
}

// processJob enriches a single IP
func (m *Manager) processJob(job EnrichmentJob, workerID int) {
	logging.Info("[THREAT_INTEL] Worker %d processing: %s (app_id: %s)", workerID, job.SourceIP, job.AppID)

	result, err := m.enricher.EnrichIP(job.AppID, job.SourceIP)
	if err != nil {
		logging.Error("[THREAT_INTEL] Worker %d enrichment failed for %s: %v (retry %d/%d)", workerID, job.SourceIP, err, job.Retry, job.MaxRetry)

		// Retry on failure
		if job.Retry < job.MaxRetry {
			job.Retry++
			time.Sleep(time.Second * time.Duration(job.Retry)) // Exponential backoff

			select {
			case m.queue <- job:
				logging.Info("[THREAT_INTEL] Requeued job for %s (retry %d)", job.SourceIP, job.Retry)
			default:
				logging.Error("[THREAT_INTEL] Failed to requeue job for %s", job.SourceIP)
			}
		}
		return
	}

	if result != nil {
		logging.Info("[THREAT_INTEL] Worker %d completed enrichment for %s: risk_score=%d threat_level=%s", workerID, job.SourceIP, result.RiskScore, result.ThreatLevel)
	}
}

// GetStats returns enrichment queue statistics
func (m *Manager) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":   m.config.Enabled,
		"workers":   m.workers,
		"queue_len": len(m.queue),
		"cache_ttl": m.config.CacheTTLHours,
	}
}
