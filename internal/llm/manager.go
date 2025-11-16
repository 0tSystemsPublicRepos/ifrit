package llm

import (
	"fmt"
	"sync"

	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

type Manager struct {
	primaryName string
	providers   map[string]Provider
	cache       map[string]interface{}
	cacheMu     sync.RWMutex
}

func NewManager(primaryProvider, claudeKey, claudeModel, geminiKey, geminiModel string) *Manager {
	m := &Manager{
		primaryName: primaryProvider,
		providers:   make(map[string]Provider),
		cache:       make(map[string]interface{}),
	}

	// Initialize Claude provider
	claudeProvider := NewClaudeProvider(claudeKey, claudeModel)
	m.providers["claude"] = claudeProvider

	// Initialize Gemini provider
	geminiProvider := NewGeminiProvider(geminiKey, geminiModel)
	m.providers["gemini"] = geminiProvider

	logging.Info("LLM Manager initialized with primary: %s | Available providers: claude, gemini", primaryProvider)
	return m
}

func (m *Manager) GetProvider(name string) interface{} {
	if provider, ok := m.providers[name]; ok {
		return provider
	}
	return nil
}

func (m *Manager) GetPrimaryName() string {
	return m.primaryName
}

func (m *Manager) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	provider, ok := m.providers[m.primaryName]
	if !ok {
		return nil, fmt.Errorf("primary provider not found: %s", m.primaryName)
	}

	result, err := provider.AnalyzeRequest(requestData)
	if err != nil {
		logging.Error("[LLM] Error analyzing request with %s: %v", m.primaryName, err)
		return nil, err
	}

	return result, nil
}

func (m *Manager) GeneratePayload(attackType string) (map[string]interface{}, error) {
	provider, ok := m.providers[m.primaryName]
	if !ok {
		return nil, fmt.Errorf("primary provider not found: %s", m.primaryName)
	}

	payload, err := provider.GeneratePayload(attackType)
	if err != nil {
		logging.Error("[LLM] Error generating payload with %s: %v", m.primaryName, err)
		return nil, err
	}

	return payload, nil
}

func (m *Manager) GetCacheStats() map[string]interface{} {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	return map[string]interface{}{
		"total_cached":        len(m.cache),
		"active_llm_payloads": 0,
		"intel_injection":     "enabled",
	}
}

func (m *Manager) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	m.cache = make(map[string]interface{})
	logging.Info("[LLM] Cache cleared")
}

func (m *Manager) CacheResult(key string, value interface{}) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	m.cache[key] = value
}

func (m *Manager) GetCachedResult(key string) (interface{}, bool) {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	val, ok := m.cache[key]
	return val, ok
}
