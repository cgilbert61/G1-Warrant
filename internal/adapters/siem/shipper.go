package siem

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// Shipper runs the single ordered PostgreSQL cursor/outbox shipping loop across all configured SIEM destinations.
// Guarantees:
//   - Strict per-stream seq_no / cursor ascending order (batching never reorders ledger records).
//   - At-least-once delivery: failed sends never advance last_acked_seq, queue behind the cursor, retry with backoff,
//     and surface last_error + failed_count + queued_count in the Console views selected by the operator.
type Shipper struct {
	store       *db.Store
	registry    *Registry
	onBroadcast func(eventType string, payload any)
	mu          sync.Mutex
	lastTick    map[string]time.Time
}

// NewShipper constructs the shared SIEM outbox shipper.
func NewShipper(store *db.Store, reg *Registry, onBroadcast func(string, any)) *Shipper {
	if reg == nil {
		reg = NewRegistry()
	}
	return &Shipper{
		store:       store,
		registry:    reg,
		onBroadcast: onBroadcast,
		lastTick:    make(map[string]time.Time),
	}
}

// Registry returns the underlying 13-SIEM sender registry.
func (s *Shipper) Registry() *Registry {
	return s.registry
}

// StartBackgroundLoop polls enabled SIEM destinations according to each destination's schedule_seconds and next_attempt_at backoff.
func (s *Shipper) StartBackgroundLoop(ctx context.Context, baseInterval time.Duration) {
	if baseInterval <= 0 {
		baseInterval = 2 * time.Second
	}
	go func() {
		ticker := time.NewTicker(baseInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.TickDueDestinations(ctx)
			}
		}
	}()
}

// TickDueDestinations evaluates all enabled SIEM destinations whose schedule_seconds / retry backoff has elapsed.
func (s *Shipper) TickDueDestinations(ctx context.Context) {
	dests, err := s.store.ListSIEMDestinations(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, d := range dests {
		if !d.Enabled {
			continue
		}
		if d.NextAttemptAt != nil && now.Before(*d.NextAttemptAt) {
			continue
		}
		sched := time.Duration(d.ScheduleSeconds) * time.Second
		if sched < time.Second {
			sched = time.Second
		}
		s.mu.Lock()
		prev := s.lastTick[d.DestinationID]
		if !prev.IsZero() && now.Sub(prev) < sched {
			s.mu.Unlock()
			continue
		}
		s.lastTick[d.DestinationID] = now
		s.mu.Unlock()

		_, _ = s.FlushDestinationNow(ctx, d.DestinationID)
	}
}

// FlushResult summarizes an immediate or scheduled SIEM flush pass for a destination.
type FlushResult struct {
	DestinationID   string                 `json:"destination_id"`
	RecordsSent     int64                  `json:"records_sent"`
	RecordsQueued   int64                  `json:"records_queued"`
	TransportStatus string                 `json:"transport_status"`
	Destination     models.SIEMDestination `json:"destination"`
}

// FlushDestinationNow ships pending ordered batches across all subscribed record types for destinationID.
func (s *Shipper) FlushDestinationNow(ctx context.Context, destinationID string) (*FlushResult, error) {
	s.mu.Lock()
	s.lastTick[destinationID] = time.Now().UTC()
	s.mu.Unlock()

	dest, err := s.store.GetSIEMDestination(ctx, destinationID)
	if err != nil {
		return nil, err
	}
	sender, err := s.registry.Get(dest.SIEMVendor)
	if err != nil {
		return nil, err
	}

	streams := uniqueStreamsForRecordTypes(dest.RecordTypes)
	cursors, err := s.store.GetSIEMStreamCursors(ctx, dest.DestinationID)
	if err != nil {
		return nil, err
	}

	computeTotalQueued := func(curMap map[string]int64) int64 {
		var total int64
		for _, st := range streams {
			cnt, cErr := s.store.CountPendingSIEMStreamRecords(ctx, st, curMap[st])
			if cErr == nil {
				total += cnt
			}
		}
		return total
	}

	secret, secErr := ResolveCredentialRef(dest.CredentialRef)
	if secErr != nil {
		backlog := computeTotalQueued(cursors)
		_ = s.store.RecordSIEMDeliveryFailure(ctx, dest.DestinationID, secErr.Error(), "CREDENTIAL_REF_ERROR", backlog)
		updated, _ := s.store.GetSIEMDestination(ctx, dest.DestinationID)
		if updated != nil {
			s.emit("SIEM_DESTINATION_UPDATED", updated)
			return &FlushResult{DestinationID: destinationID, RecordsQueued: backlog, TransportStatus: "CREDENTIAL_REF_ERROR", Destination: *updated}, secErr
		}
		return nil, secErr
	}

	batchSize := dest.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	} else if batchSize > 500 {
		batchSize = 500
	}

	var totalSent int64
	lastStatus := dest.LastTransportStatus

	// Drain up to 20 ordered batches per flush pass so proof runs and catch-ups converge quickly without starving other destinations
	for pass := 0; pass < 20; pass++ {
		progressedInPass := false
		for _, streamName := range streams {
			afterSeq := cursors[streamName]
			batch, fErr := s.store.FetchOrderedSIEMStreamBatch(ctx, streamName, afterSeq, batchSize)
			if fErr != nil {
				backlog := computeTotalQueued(cursors)
				_ = s.store.RecordSIEMDeliveryFailure(ctx, dest.DestinationID, fErr.Error(), "DB_READ_ERROR", backlog)
				return nil, fErr
			}
			if len(batch) == 0 {
				continue
			}

			// Verify strict monotonic cursor order before transmitting
			for i := 1; i < len(batch); i++ {
				if batch[i].CursorSeq < batch[i-1].CursorSeq {
					err := fmt.Errorf("LEDGER_ORDER_INVARIANT_VIOLATION on %s: %d < %d", streamName, batch[i].CursorSeq, batch[i-1].CursorSeq)
					_ = s.store.RecordSIEMDeliveryFailure(ctx, dest.DestinationID, err.Error(), "ORDER_VIOLATION", computeTotalQueued(cursors))
					return nil, err
				}
			}

			tStatus, sendErr := sender.SendBatch(ctx, *dest, secret, batch)
			if sendErr != nil {
				backlog := computeTotalQueued(cursors)
				_ = s.store.RecordSIEMDeliveryFailure(ctx, dest.DestinationID, sendErr.Error(), tStatus, backlog)
				updated, _ := s.store.GetSIEMDestination(ctx, dest.DestinationID)
				if updated != nil {
					s.emit("SIEM_DESTINATION_UPDATED", updated)
					return &FlushResult{
						DestinationID:   destinationID,
						RecordsSent:     totalSent,
						RecordsQueued:   backlog,
						TransportStatus: tStatus,
						Destination:     *updated,
					}, sendErr
				}
				return nil, sendErr
			}

			highestAck := batch[len(batch)-1].CursorSeq
			if err := s.store.RecordSIEMStreamBatchAck(ctx, dest.DestinationID, streamName, highestAck, int64(len(batch)), tStatus); err != nil {
				return nil, err
			}
			cursors[streamName] = highestAck
			totalSent += int64(len(batch))
			lastStatus = tStatus
			progressedInPass = true
		}
		if !progressedInPass {
			break
		}
	}

	remaining := computeTotalQueued(cursors)
	_ = s.store.UpdateSIEMQueuedCount(ctx, dest.DestinationID, remaining)
	updated, err := s.store.GetSIEMDestination(ctx, dest.DestinationID)
	if err != nil {
		return nil, err
	}
	s.emit("SIEM_DESTINATION_UPDATED", updated)
	return &FlushResult{
		DestinationID:   destinationID,
		RecordsSent:     totalSent,
		RecordsQueued:   remaining,
		TransportStatus: lastStatus,
		Destination:     *updated,
	}, nil
}

func uniqueStreamsForRecordTypes(recTypes []string) []string {
	if len(recTypes) == 0 {
		recTypes = []string{
			models.SIEMRecordSignedClosure,
			models.SIEMRecordWORMLedger,
			models.SIEMRecordAuthClassSigning,
			models.SIEMRecordDispatchResult,
			models.SIEMRecordShieldEvent,
			models.SIEMRecordTwinProofVerdict,
			models.SIEMRecordIngestEvent,
			models.SIEMRecordSIEMConfigAudit,
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, rt := range recTypes {
		for _, st := range db.StreamsForSIEMRecordType(rt) {
			if !seen[st] {
				seen[st] = true
				out = append(out, st)
			}
		}
	}
	return out
}

func (s *Shipper) emit(eventType string, payload any) {
	if s.onBroadcast != nil {
		s.onBroadcast(eventType, payload)
	}
}
