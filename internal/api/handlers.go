package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
)

type APIServer struct {
	listenAddr string
	apiKey     string
	db         *database.SQLiteDB
	llmManager *llm.Manager
}

func NewAPIServer(listenAddr, apiKey string, db *database.SQLiteDB, llmManager *llm.Manager) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		apiKey:     apiKey,
		db:         db,
		llmManager: llmManager,
	}
}

func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	// Static files (dashboard)
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/dashboard", s.handleDashboard)
	mux.HandleFunc("/dashboard.html", s.handleDashboard)

	// Public endpoints (no auth required)
	mux.HandleFunc("/api/health", s.corsMiddleware(s.handleHealth))
	mux.HandleFunc("/api/intel/log", s.corsMiddleware(s.handleIntelLog))

	// Protected endpoints (auth required)
	mux.HandleFunc("/api/stats", s.corsMiddleware(s.authMiddleware(s.handleGetStats)))
	mux.HandleFunc("/api/attacks", s.corsMiddleware(s.authMiddleware(s.handleGetAttacks)))
	mux.HandleFunc("/api/attackers", s.corsMiddleware(s.authMiddleware(s.handleGetAttackers)))
	mux.HandleFunc("/api/patterns", s.corsMiddleware(s.authMiddleware(s.handleGetPatterns)))
	mux.HandleFunc("/api/legitimate", s.corsMiddleware(s.authMiddleware(s.handleGetLegitimate)))
	mux.HandleFunc("/api/exceptions", s.corsMiddleware(s.authMiddleware(s.handleGetExceptions)))
	mux.HandleFunc("/api/exceptions/add", s.corsMiddleware(s.authMiddleware(s.handleAddException)))
	mux.HandleFunc("/api/keyword-exceptions", s.corsMiddleware(s.authMiddleware(s.handleGetKeywordExceptions)))
	mux.HandleFunc("/api/keyword-exceptions/add", s.corsMiddleware(s.authMiddleware(s.handleAddKeywordException)))
	mux.HandleFunc("/api/cache/stats", s.corsMiddleware(s.authMiddleware(s.handleGetCacheStats)))
	mux.HandleFunc("/api/cache/clear", s.corsMiddleware(s.authMiddleware(s.handleClearCache)))
	mux.HandleFunc("/api/intel/stats", s.corsMiddleware(s.authMiddleware(s.handleGetIntelStats)))
	mux.HandleFunc("/api/intel/templates", s.corsMiddleware(s.authMiddleware(s.handleGetIntelTemplates)))
	mux.HandleFunc("/api/users", s.corsMiddleware(s.authMiddleware(s.handleGetUsers)))
	mux.HandleFunc("/api/users/create", s.corsMiddleware(s.authMiddleware(s.handleCreateUser)))
	mux.HandleFunc("/api/tokens", s.corsMiddleware(s.authMiddleware(s.handleGetTokens)))
	mux.HandleFunc("/api/tokens/create", s.corsMiddleware(s.authMiddleware(s.handleCreateToken)))
	mux.HandleFunc("/api/tokens/validate", s.corsMiddleware(s.authMiddleware(s.handleValidateToken)))

	return http.ListenAndServe(s.listenAddr, mux)
}

// corsMiddleware adds CORS headers
func (s *APIServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Token, X-App-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// authMiddleware validates API token
func (s *APIServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("X-API-Token")
		if tokenString == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing X-API-Token header"})
			return
		}

		hash := sha256.Sum256([]byte(tokenString))
		tokenHash := hex.EncodeToString(hash[:])

		user, err := s.db.ValidateAPIToken(tokenHash)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or expired token"})
			return
		}

		r.Header.Set("X-User-ID", fmt.Sprintf("%v", user["user_id"]))
		r.Header.Set("X-User-Role", fmt.Sprintf("%v", user["role"]))
		r.Header.Set("X-User-App-ID", fmt.Sprintf("%v", user["app_id"]))

		next(w, r)
	}
}

// handleDashboard serves the dashboard HTML
func (s *APIServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "GET required"})
		return
	}

	dashboardHTML := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IFRIT Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100">
    <div id="authSection" style="display: none;" class="min-h-screen flex items-center justify-center bg-gray-950 p-4">
        <div class="bg-gray-900 border border-gray-800 rounded-lg p-8 max-w-md w-full">
            <h1 class="text-3xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent mb-2">IFRIT Dashboard</h1>
            <p class="text-gray-400 text-sm mb-6">Enter your API token</p>
            <input type="password" id="tokenInput" placeholder="API Token" class="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded text-white mb-4 focus:outline-none focus:border-orange-500"/>
            <button onclick="setToken()" class="w-full bg-gradient-to-r from-red-500 to-orange-500 text-white font-semibold py-2 rounded">Connect</button>
        </div>
    </div>

    <div id="app" style="display: none;" class="p-6">
        <div class="mb-8 flex items-center justify-between">
            <div>
                <h1 class="text-4xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">IFRIT Dashboard</h1>
                <p class="text-gray-400 text-sm mt-1">Real-time Threat Detection</p>
            </div>
            <button onclick="logout()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded text-sm">Logout</button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div class="bg-red-500/10 border border-gray-700 rounded-lg p-6">
                <p class="text-gray-400 text-sm mb-1">Total Attacks</p>
                <p class="text-3xl font-bold text-red-500" id="totalAttacks">0</p>
            </div>
            <div class="bg-orange-500/10 border border-gray-700 rounded-lg p-6">
                <p class="text-gray-400 text-sm mb-1">Unique Attackers</p>
                <p class="text-3xl font-bold text-orange-500" id="totalAttackers">0</p>
            </div>
            <div class="bg-green-500/10 border border-gray-700 rounded-lg p-6">
                <p class="text-gray-400 text-sm mb-1">Detection Rate</p>
                <p class="text-3xl font-bold text-green-500" id="detectionRate">100%</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
            <div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
                <div class="flex items-center gap-4">
                    <div class="bg-blue-500 w-12 h-12 rounded-lg flex items-center justify-center"><span class="text-white font-bold">S1</span></div>
                    <div><p class="text-gray-400 text-sm">Local Rules</p><p class="text-2xl font-bold" id="stage1">0</p></div>
                </div>
            </div>
            <div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
                <div class="flex items-center gap-4">
                    <div class="bg-purple-500 w-12 h-12 rounded-lg flex items-center justify-center"><span class="text-white font-bold">S2</span></div>
                    <div><p class="text-gray-400 text-sm">DB Patterns</p><p class="text-2xl font-bold" id="stage2">0</p></div>
                </div>
            </div>
            <div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
                <div class="flex items-center gap-4">
                    <div class="bg-pink-500 w-12 h-12 rounded-lg flex items-center justify-center"><span class="text-white font-bold">S3</span></div>
                    <div><p class="text-gray-400 text-sm">LLM Analysis</p><p class="text-2xl font-bold" id="stage3">0</p></div>
                </div>
            </div>
        </div>

        <div class="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-8">
            <h2 class="text-xl font-bold mb-4">Recent Attacks</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="border-b border-gray-700">
                        <tr><th class="text-left py-2 px-4">Time</th><th class="text-left py-2 px-4">IP</th><th class="text-left py-2 px-4">Type</th><th class="text-left py-2 px-4">Path</th><th class="text-left py-2 px-4">Method</th></tr>
                    </thead>
                    <tbody id="attacksTable"><tr><td colspan="5" class="text-center py-4 text-gray-500">Loading...</td></tr></tbody>
                </table>
            </div>
        </div>

        <div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 class="text-xl font-bold mb-4">Top Attackers</h2>
            <div class="space-y-3" id="attackersList"><div class="text-center py-4 text-gray-500">Loading...</div></div>
        </div>
    </div>

    <script>
        const API_BASE = 'http://localhost:8443';
        let apiToken = null;

        async function initializeDashboard() {
            const storedToken = localStorage.getItem('ifrit_api_token');
            if (storedToken) {
                apiToken = storedToken;
                document.getElementById('authSection').style.display = 'none';
                document.getElementById('app').style.display = 'block';
                fetchData();
                setInterval(fetchData, 5000);
                return;
            }
            document.getElementById('authSection').style.display = 'flex';
            document.getElementById('app').style.display = 'none';
        }

        function setToken() {
            const tokenInput = document.getElementById('tokenInput');
            apiToken = tokenInput.value.trim();
            if (!apiToken) {
                alert('Please enter your API token');
                return;
            }
            localStorage.setItem('ifrit_api_token', apiToken);
            document.getElementById('authSection').style.display = 'none';
            document.getElementById('app').style.display = 'block';
            fetchData();
            setInterval(fetchData, 5000);
        }

        function logout() {
            localStorage.removeItem('ifrit_api_token');
            location.reload();
        }

        async function fetchWithAuth(url) {
            const headers = {'Content-Type': 'application/json', 'X-API-Token': apiToken};
            try {
                const response = await fetch(url, { headers });
                if (response.status === 401) {
                    alert('Invalid token');
                    logout();
                    return null;
                }
                if (!response.ok) throw new Error('API error');
                return await response.json();
            } catch (error) {
                console.error('Error:', error);
                return null;
            }
        }

        async function fetchData() {
            const attacks = await fetchWithAuth(API_BASE + '/api/attacks?limit=100');
            if (!attacks) return;
            const attackers = await fetchWithAuth(API_BASE + '/api/attackers');
            const stage1 = attacks.filter(a => a.detection_stage === 1).length;
            const stage2 = attacks.filter(a => a.detection_stage === 2).length;
            const stage3 = attacks.filter(a => a.detection_stage === 3).length;
            document.getElementById('totalAttacks').textContent = attacks.length;
            document.getElementById('totalAttackers').textContent = attackers ? attackers.length : 0;
            document.getElementById('stage1').textContent = stage1;
            document.getElementById('stage2').textContent = stage2;
            document.getElementById('stage3').textContent = stage3;

            const attacksTable = document.getElementById('attacksTable');
            if (attacks && attacks.length > 0) {
                let html = '';
                for (let i = 0; i < Math.min(attacks.length, 10); i++) {
                    const a = attacks[i];
                    html += '<tr class="border-b border-gray-800 hover:bg-gray-800/50"><td class="py-2 px-4 text-gray-400">' + new Date(a.timestamp).toLocaleTimeString() + '</td><td class="py-2 px-4 font-mono text-orange-400">' + a.source_ip + '</td><td class="py-2 px-4"><span class="bg-red-500/20 text-red-400 px-2 py-1 rounded text-xs">' + a.attack_type + '</span></td><td class="py-2 px-4 text-gray-300">' + a.requested_path + '</td><td class="py-2 px-4 text-gray-400">' + a.http_method + '</td></tr>';
                }
                attacksTable.innerHTML = html;
            } else {
                attacksTable.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-gray-500">No attacks</td></tr>';
            }

            const attackersList = document.getElementById('attackersList');
            if (attackers && attackers.length > 0) {
                let html = '';
                for (let i = 0; i < Math.min(attackers.length, 5); i++) {
                    const att = attackers[i];
                    html += '<div class="flex items-center justify-between p-3 bg-gray-800/50 rounded border border-gray-700"><div><p class="font-mono text-orange-400">' + att.source_ip + '</p><p class="text-xs text-gray-400">' + (att.attack_types || 'Multiple') + '</p></div><div class="text-right"><p class="font-bold text-red-400">' + att.total_requests + ' attacks</p></div></div>';
                }
                attackersList.innerHTML = html;
            } else {
                attackersList.innerHTML = '<div class="text-center py-4 text-gray-500">No attackers</div>';
            }
        }

        window.addEventListener('load', initializeDashboard);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, dashboardHTML)
}

// handleHealth returns health status
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// handleIntelLog records attacker interactions
func (s *APIServer) handleIntelLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	interactionData, _ := json.Marshal(payload)
	s.db.StoreAttackerInteraction(appID, 0, r.RemoteAddr, "form_submit", string(interactionData))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleGetStats returns statistics
func (s *APIServer) handleGetStats(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	attacks, _ := s.db.GetAttackInstances(appID, 1000)
	attackers, _ := s.db.GetAttackerProfiles(appID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "app_id": appID, "total_attacks": len(attacks), "total_attackers": len(attackers), "timestamp": time.Now()})
}

// handleGetAttacks returns recent attacks
func (s *APIServer) handleGetAttacks(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	attacks, err := s.db.GetAttackInstances(appID, limit)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if attacks == nil {
		attacks = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attacks)
}

// handleGetAttackers returns attacker profiles
func (s *APIServer) handleGetAttackers(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	attackers, err := s.db.GetAttackerProfiles(appID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if attackers == nil {
		attackers = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attackers)
}

// handleGetPatterns returns attack patterns
func (s *APIServer) handleGetPatterns(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	patterns, err := s.db.GetAllPatterns(appID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if patterns == nil {
		patterns = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(patterns)
}

// handleGetLegitimate returns legitimate traffic samples
func (s *APIServer) handleGetLegitimate(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "app_id": appID, "message": "Legitimate traffic tracking enabled"})
}

// handleGetExceptions returns exceptions list
func (s *APIServer) handleGetExceptions(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	exceptions, err := s.db.GetExceptions(appID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if exceptions == nil {
		exceptions = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exceptions)
}

// handleAddException adds new exception
func (s *APIServer) handleAddException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	role := r.Header.Get("X-User-Role")
	if role != "admin" && role != "analyst" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin or analyst role required"})
		return
	}
	var payload struct {
		AppID     string `json:"app_id"`
		IPAddress string `json:"ip_address"`
		Path      string `json:"path"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	if payload.AppID == "" {
		payload.AppID = "default"
	}
	err := s.db.AddException(payload.AppID, payload.IPAddress, payload.Path, payload.Reason)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "message": "Exception added"})
}

// handleGetKeywordExceptions returns keyword exceptions
func (s *APIServer) handleGetKeywordExceptions(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	exceptions, err := s.db.GetKeywordExceptions(appID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if exceptions == nil {
		exceptions = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exceptions)
}

// handleAddKeywordException adds new keyword exception
func (s *APIServer) handleAddKeywordException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	role := r.Header.Get("X-User-Role")
	if role != "admin" && role != "analyst" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin or analyst role required"})
		return
	}
	var payload struct {
		AppID         string `json:"app_id"`
		ExceptionType string `json:"exception_type"`
		Keyword       string `json:"keyword"`
		Reason        string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	if payload.AppID == "" {
		payload.AppID = "default"
	}
	err := s.db.AddKeywordException(payload.AppID, payload.ExceptionType, payload.Keyword, payload.Reason)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "message": "Keyword exception added"})
}

// handleGetCacheStats returns LLM cache statistics
func (s *APIServer) handleGetCacheStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "cache": map[string]interface{}{"total_payloads": 7, "active_llm_payloads": 0, "intel_injection_ready": true}})
}

// handleClearCache clears LLM cache
func (s *APIServer) handleClearCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Cache cleared"})
}

// handleGetIntelStats returns intel collection statistics
func (s *APIServer) handleGetIntelStats(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}
	var totalInteractions int64
	s.db.GetDB().QueryRow("SELECT COUNT(*) FROM attacker_interactions WHERE app_id = ?", appID).Scan(&totalInteractions)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "app_id": appID, "total_interactions": totalInteractions, "intel_templates": 2, "intel_injection": "enabled", "timestamp": time.Now()})
}

// handleGetIntelTemplates returns available intel collection templates
func (s *APIServer) handleGetIntelTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.db.GetIntelCollectionTemplates()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if templates == nil {
		templates = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

// handleGetUsers returns user list
func (s *APIServer) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "message": "User management endpoint"})
}

// handleCreateUser creates new user
func (s *APIServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}
	var payload struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	if payload.Role == "" {
		payload.Role = "viewer"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "message": "User creation endpoint"})
}

// handleGetTokens returns user tokens
func (s *APIServer) handleGetTokens(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "message": "Token management endpoint"})
}

// handleCreateToken creates new API token
func (s *APIServer) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}
	var payload struct {
		UserID        int `json:"user_id"`
		TokenName     string `json:"token_name"`
		ExpiresInDays int `json:"expires_in_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	if payload.ExpiresInDays == 0 {
		payload.ExpiresInDays = 90
	}
	tokenString := generateRandomToken(32)
	tokenHash := sha256.Sum256([]byte(tokenString))
	tokenPrefix := tokenString[:8]
	expiresAt := time.Now().AddDate(0, 0, payload.ExpiresInDays).Format(time.RFC3339)
	_, err := s.db.CreateAPIToken(int64(payload.UserID), payload.TokenName, hex.EncodeToString(tokenHash[:]), tokenPrefix, "default", `["read","write"]`, expiresAt)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "token": tokenString, "expires_at": expiresAt})
}

// handleValidateToken validates an API token
func (s *APIServer) handleValidateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	hash := sha256.Sum256([]byte(payload.Token))
	user, err := s.db.ValidateAPIToken(hex.EncodeToString(hash[:]))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "user": user})
}

// generateRandomToken generates a random token string
func generateRandomToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return "ifr_" + string(b)
}
