package agenttelemetry

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

type fakeReporter struct{ usage []controlclient.SessionUsage }

func (f *fakeReporter) PutSessionUsage(_ context.Context, _ string, usage controlclient.SessionUsage) error {
	f.usage = append(f.usage, usage)
	return nil
}

func TestCodexCompletionLogReportsMonotonicUsageOnce(t *testing.T) {
	reporter := &fakeReporter{}
	c := &Collector{reporter: reporter, sessionID: "session", seenLogs: map[string]struct{}{}, counters: map[string]int64{}}
	request := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{}, ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			EventName: "codex.sse_event",
			Body:      stringValue(`{"type":"response.completed","response":{"usage":{"input_tokens":21,"output_tokens":8},"model":"gpt-test"}}`),
		}}}},
	}}}
	encoded, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(encoded))
		c.logs(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
		}
	}
	if len(reporter.usage) != 1 || reporter.usage[0].InputTokens != 21 || reporter.usage[0].OutputTokens != 8 || reporter.usage[0].Model != "gpt-test" {
		t.Fatalf("unexpected usage: %#v", reporter.usage)
	}
}

func TestClaudeCumulativeMetricsReportOnlyTheIncrease(t *testing.T) {
	reporter := &fakeReporter{}
	c := &Collector{reporter: reporter, sessionID: "session", seenLogs: map[string]struct{}{}, counters: map[string]int64{}}
	for _, value := range []int64{10, 15} {
		request := metricRequest(value)
		encoded, err := proto.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(encoded))
		c.metrics(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
		}
	}
	if len(reporter.usage) != 2 || reporter.usage[0].InputTokens != 10 || reporter.usage[1].InputTokens != 15 {
		t.Fatalf("unexpected cumulative usage: %#v", reporter.usage)
	}
}

func metricRequest(value int64) *collectormetricspb.ExportMetricsServiceRequest {
	return &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{}, ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "claude_code.token.usage",
			Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
				AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				IsMonotonic:            true,
				DataPoints: []*metricspb.NumberDataPoint{{
					Attributes: []*commonpb.KeyValue{{Key: "type", Value: stringValue("input")}, {Key: "model", Value: stringValue("claude-test")}},
					Value:      &metricspb.NumberDataPoint_AsInt{AsInt: value},
				}},
			}},
		}}}},
	}}}
}

func stringValue(value string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
}
