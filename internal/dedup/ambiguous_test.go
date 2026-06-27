package dedup

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestResolveAmbiguous_Empty(t *testing.T) {
	_, ok := ResolveAmbiguous(nil)
	if !ok {
		t.Error("empty edges must be unambiguous (insert path)")
	}
}

func TestResolveAmbiguous_SingleAsset(t *testing.T) {
	id := uuid.Must(uuid.NewV7())
	canonical, ok := ResolveAmbiguous([]AliasEdge{
		{AssetID: id, SignalKind: "k", SignalHash: "h"},
		{AssetID: id, SignalKind: "k", SignalHash: "h"},
	})
	if !ok || canonical != id {
		t.Errorf("single-asset edges must collapse: ok=%v id=%v", ok, canonical)
	}
}

func TestResolveAmbiguous_MultiAsset(t *testing.T) {
	a := uuid.Must(uuid.NewV7())
	b := uuid.Must(uuid.NewV7())
	_, ok := ResolveAmbiguous([]AliasEdge{
		{AssetID: a}, {AssetID: b},
	})
	if ok {
		t.Error("multi-asset edges must be ambiguous")
	}
}

func TestAliasEdgesFromSignals_HashesPerSignal(t *testing.T) {
	id := uuid.Must(uuid.NewV7())
	now := time.Now()
	edges := AliasEdgesFromSignals(id, "src", ConfidenceHardware, now, []Signal{
		{Kind: "a", Bytes: []byte("one")},
		{Kind: "b", Bytes: []byte("two")},
	})
	if len(edges) != 2 {
		t.Fatalf("len = %d, want 2", len(edges))
	}
	if edges[0].SignalHash == edges[1].SignalHash {
		t.Error("distinct signal bytes must hash differently")
	}
	if edges[0].AssetID != id || edges[0].Confidence != ConfidenceHardware {
		t.Error("edge fields not propagated")
	}
}

func TestNewAmbiguousMerge_PopulatesAndDefers(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	asset := model.Asset{Hostname: "h", AssetType: model.AssetTypeServer}
	sig := Signal{Kind: "instance_id", Bytes: []byte("i-abc")}
	ev := NewAmbiguousMerge(now, "t", "agent", asset, sig, "i-abc", nil)
	if ev.Resolution != AmbiguousResolutionDeferred {
		t.Errorf("resolution = %s, want deferred", ev.Resolution)
	}
	if ev.DetectedAt != now.UTC() {
		t.Error("DetectedAt not set")
	}
	if ev.Signal.Hash == "" {
		t.Error("Signal.Hash not computed")
	}
	if ev.Signal.Value != "i-abc" {
		t.Errorf("Signal.Value = %q", ev.Signal.Value)
	}
}
