package agenttelemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

const maximumPayloadBytes = 4 << 20

type Reporter interface {
	PutSessionUsage(context.Context, string, controlclient.SessionUsage) error
}

type Collector struct {
	reporter  Reporter
	sessionID string
	server    *http.Server
	listener  net.Listener

	mu           sync.Mutex
	inputTokens  int64
	outputTokens int64
	model        string
	seenLogs     map[string]struct{}
	counters     map[string]int64
}

func Start(reporter Reporter, sessionID string) (*Collector, error) {
	if reporter == nil || strings.TrimSpace(sessionID) == "" {
		return nil, errors.New("telemetry reporter and session are required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for native agent telemetry: %w", err)
	}
	c := &Collector{reporter: reporter, sessionID: sessionID, listener: listener, seenLogs: map[string]struct{}{}, counters: map[string]int64{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/logs", c.logs)
	mux.HandleFunc("POST /v1/metrics", c.metrics)
	c.server = &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = c.server.Serve(listener) }()
	return c, nil
}

func (c *Collector) URL() string { return "http://" + c.listener.Addr().String() }

func (c *Collector) Close(ctx context.Context) error { return c.server.Shutdown(ctx) }

func (c *Collector) logs(w http.ResponseWriter, r *http.Request) {
	body, ok := readProtobuf(w, r)
	if !ok {
		return
	}
	var request collectorlogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &request); err != nil {
		http.Error(w, "invalid telemetry", http.StatusBadRequest)
		return
	}
	var input, output int64
	model := ""
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	c.mu.Lock()
	if _, exists := c.seenLogs[digestText]; exists {
		c.mu.Unlock()
		writeProtobuf(w, &collectorlogspb.ExportLogsServiceResponse{})
		return
	}
	for _, resource := range request.ResourceLogs {
		for _, scope := range resource.ScopeLogs {
			for _, record := range scope.LogRecords {
				values := attributeMap(record.Attributes)
				values["event.name"] = record.EventName
				values["body"] = anyValue(record.Body)
				if !looksLikeCodexCompletion(values) {
					continue
				}
				input += findTokenCount(values, "input")
				output += findTokenCount(values, "output")
				if candidate := findString(values, "model"); candidate != "" {
					model = candidate
				}
			}
		}
	}
	if input == 0 && output == 0 && model == "" {
		c.mu.Unlock()
		writeProtobuf(w, &collectorlogspb.ExportLogsServiceResponse{})
		return
	}
	usage := controlclient.SessionUsage{InputTokens: c.inputTokens + input, OutputTokens: c.outputTokens + output, Model: firstNonEmpty(model, c.model)}
	if !c.report(r.Context(), usage) {
		c.mu.Unlock()
		http.Error(w, "telemetry delivery failed", http.StatusServiceUnavailable)
		return
	}
	c.inputTokens, c.outputTokens, c.model = usage.InputTokens, usage.OutputTokens, usage.Model
	c.seenLogs[digestText] = struct{}{}
	c.mu.Unlock()
	writeProtobuf(w, &collectorlogspb.ExportLogsServiceResponse{})
}

func (c *Collector) metrics(w http.ResponseWriter, r *http.Request) {
	body, ok := readProtobuf(w, r)
	if !ok {
		return
	}
	var request collectormetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(body, &request); err != nil {
		http.Error(w, "invalid telemetry", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	inputTotal, outputTotal, model := c.inputTokens, c.outputTokens, c.model
	nextCounters := make(map[string]int64, len(c.counters))
	for key, value := range c.counters {
		nextCounters[key] = value
	}
	changed := false
	for _, resource := range request.ResourceMetrics {
		for _, scope := range resource.ScopeMetrics {
			for _, metric := range scope.Metrics {
				name := strings.ToLower(metric.Name)
				if !strings.Contains(name, "token") || !strings.Contains(name, "usage") {
					continue
				}
				sum := metric.GetSum()
				if sum == nil {
					continue
				}
				for _, point := range sum.DataPoints {
					attrs := attributeMap(point.Attributes)
					kind := strings.ToLower(findString(attrs, "type", "token.type", "token_type"))
					candidateModel := findString(attrs, "model", "model.name", "model_name")
					value := numberPoint(point)
					if value < 0 {
						continue
					}
					key := name + "\x00" + kind + "\x00" + candidateModel
					previous := c.counters[key]
					delta := value
					if sum.AggregationTemporality == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE {
						if value <= previous {
							delta = 0
						} else {
							delta = value - previous
						}
					}
					if value > previous {
						nextCounters[key] = value
					}
					switch kind {
					case "input", "input_tokens", "prompt":
						inputTotal += delta
					case "output", "output_tokens", "completion":
						outputTotal += delta
					default:
						continue
					}
					changed = changed || delta > 0
					if candidateModel != "" {
						model = candidateModel
					}
				}
			}
		}
	}
	if !changed && model == c.model {
		c.mu.Unlock()
		writeProtobuf(w, &collectormetricspb.ExportMetricsServiceResponse{})
		return
	}
	usage := controlclient.SessionUsage{InputTokens: inputTotal, OutputTokens: outputTotal, Model: model}
	if !c.report(r.Context(), usage) {
		c.mu.Unlock()
		http.Error(w, "telemetry delivery failed", http.StatusServiceUnavailable)
		return
	}
	c.inputTokens, c.outputTokens, c.model = usage.InputTokens, usage.OutputTokens, usage.Model
	c.counters = nextCounters
	c.mu.Unlock()
	writeProtobuf(w, &collectormetricspb.ExportMetricsServiceResponse{})
}

func (c *Collector) report(parent context.Context, usage controlclient.SessionUsage) bool {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	return c.reporter.PutSessionUsage(ctx, c.sessionID, usage) == nil
}

func readProtobuf(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maximumPayloadBytes))
	if err != nil {
		http.Error(w, "telemetry payload too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return body, true
}

func writeProtobuf(w http.ResponseWriter, message proto.Message) {
	encoded, _ := proto.Marshal(message)
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func attributeMap(values []*commonpb.KeyValue) map[string]any {
	result := make(map[string]any, len(values))
	for _, value := range values {
		result[value.Key] = anyValue(value.Value)
	}
	return result
}

func anyValue(value *commonpb.AnyValue) any {
	if value == nil {
		return nil
	}
	switch typed := value.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		var decoded any
		if json.Unmarshal([]byte(typed.StringValue), &decoded) == nil {
			return decoded
		}
		return typed.StringValue
	case *commonpb.AnyValue_IntValue:
		return typed.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return typed.DoubleValue
	case *commonpb.AnyValue_BoolValue:
		return typed.BoolValue
	case *commonpb.AnyValue_KvlistValue:
		return attributeMap(typed.KvlistValue.Values)
	case *commonpb.AnyValue_ArrayValue:
		items := make([]any, 0, len(typed.ArrayValue.Values))
		for _, item := range typed.ArrayValue.Values {
			items = append(items, anyValue(item))
		}
		return items
	default:
		return nil
	}
}

func looksLikeCodexCompletion(values map[string]any) bool {
	flat, _ := json.Marshal(values)
	text := strings.ToLower(string(flat))
	return strings.Contains(text, "response.completed") || (strings.Contains(text, "codex.sse_event") && strings.Contains(text, "token"))
}

func findTokenCount(value any, direction string) int64 {
	var total int64
	var walk func(any, string)
	walk = func(current any, path string) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				walk(child, strings.ToLower(path+"."+key))
			}
		case []any:
			for _, child := range typed {
				walk(child, path)
			}
		case float64:
			if strings.Contains(path, direction) && strings.Contains(path, "token") && typed >= 0 && typed <= math.MaxInt64 {
				total += int64(typed)
			}
		case int64:
			if strings.Contains(path, direction) && strings.Contains(path, "token") && typed >= 0 {
				total += typed
			}
		}
	}
	walk(value, "")
	return total
}

func findString(values map[string]any, keys ...string) string {
	if len(keys) == 0 {
		keys = []string{"model", "model.name", "model_name"}
	}
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	for key, value := range values {
		for _, wanted := range keys {
			if strings.Contains(strings.ToLower(key), strings.ToLower(wanted)) {
				if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
					return strings.TrimSpace(text)
				}
			}
		}
		if nested, ok := value.(map[string]any); ok {
			if found := findString(nested, keys...); found != "" {
				return found
			}
		}
	}
	return ""
}

func numberPoint(point *metricspb.NumberDataPoint) int64 {
	switch point.Value.(type) {
	case *metricspb.NumberDataPoint_AsInt:
		return point.GetAsInt()
	case *metricspb.NumberDataPoint_AsDouble:
		return int64(point.GetAsDouble())
	default:
		return -1
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
