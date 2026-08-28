package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBodySize = 1 << 20

type application struct {
	correlationPath string
	bpfPath         string
	metricsURL      string

	mu          sync.RWMutex
	alerts      []json.RawMessage
	subscribers map[chan []byte]struct{}
}

func main() {
	app := &application{
		correlationPath: env("EAD_CORRELATION_CONFIG", projectFile("analyzer/build/correlation-config.json")),
		bpfPath:         env("EAD_BPF_CONFIG", projectFile("host/build/bpf-config.json")),
		metricsURL:      env("EAD_METRICS_URL", "http://127.0.0.1:9200/metrics"),
		subscribers:     make(map[chan []byte]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.index)
	mux.HandleFunc("GET /api/config/{name}", app.getConfig)
	mux.HandleFunc("PUT /api/config/{name}", app.putConfig)
	mux.HandleFunc("GET /api/alerts/count", app.alertCount)
	mux.HandleFunc("GET /api/alerts", app.alertStream)
	mux.HandleFunc("POST /api/alerts", app.receiveAlert)

	address := env("EAD_WEB_ADDR", ":8080")
	log.Printf("EAD web interface is listening on %s", address)
	log.Fatal(http.ListenAndServe(address, logging(mux)))
}

func projectFile(relativePath string) string {
	var candidates []string
	if _, sourceFile, _, ok := runtime.Caller(0); ok {
		projectRoot := filepath.Dir(filepath.Dir(sourceFile))
		candidates = append(candidates, filepath.Join(projectRoot, relativePath))
	}

	workingDirectory, err := os.Getwd()
	if err == nil {
		directory := workingDirectory
		for {
			candidates = append(candidates, filepath.Join(directory, relativePath))
			parent := filepath.Dir(directory)
			if parent == directory {
				break
			}
			directory = parent
		}
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("..", relativePath)
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func (app *application) configPath(name string) (string, bool) {
	switch name {
	case "correlation":
		return app.correlationPath, true
	case "bpf":
		return app.bpfPath, true
	default:
		return "", false
	}
}

func (app *application) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

func (app *application) getConfig(w http.ResponseWriter, r *http.Request) {
	path, ok := app.configPath(r.PathValue("name"))
	if !ok {
		http.Error(w, "unknown config", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (app *application) putConfig(w http.ResponseWriter, r *http.Request) {
	path, ok := app.configPath(r.PathValue("name"))
	if !ok {
		http.Error(w, "unknown config", http.StatusNotFound)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "config is too large", http.StatusRequestEntityTooLarge)
		return
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	formatted, _ := json.MarshalIndent(value, "", "    ")
	formatted = append(formatted, '\n')
	if err := atomicWrite(path, formatted); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func atomicWrite(path string, data []byte) error {
	directory := filepath.Dir(path)
	mode := os.FileMode(0644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	temporary, err := os.CreateTemp(directory, ".ead-config-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err = temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err = temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func (app *application) receiveAlert(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil || !json.Valid(data) {
		http.Error(w, "invalid alert JSON", http.StatusBadRequest)
		return
	}
	data = append([]byte(nil), data...)
	app.mu.Lock()
	app.alerts = append(app.alerts, json.RawMessage(data))
	if len(app.alerts) > 500 {
		app.alerts = app.alerts[len(app.alerts)-500:]
	}
	for subscriber := range app.subscribers {
		select {
		case subscriber <- data:
		default:
		}
	}
	app.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (app *application) alertStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	updates := make(chan []byte, 32)
	app.mu.Lock()
	history := append([]json.RawMessage(nil), app.alerts...)
	app.subscribers[updates] = struct{}{}
	app.mu.Unlock()
	defer func() {
		app.mu.Lock()
		delete(app.subscribers, updates)
		app.mu.Unlock()
	}()
	for _, alert := range history {
		fmt.Fprintf(w, "data: %s\n\n", alert)
	}
	flusher.Flush()
	for {
		select {
		case alert := <-updates:
			fmt.Fprintf(w, "data: %s\n\n", alert)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (app *application) alertCount(w http.ResponseWriter, _ *http.Request) {
	count, err := prometheusCounter(app.metricsURL, "ead_alerts_total")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"count":%s}`, strconv.FormatFloat(count, 'f', -1, 64))
}

func prometheusCounter(url, metric string) (float64, error) {
	client := http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, errors.New(response.Status)
	}
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == metric {
			return strconv.ParseFloat(fields[1], 64)
		}
	}
	return 0, scanner.Err()
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
