package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/adapters/siem"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

var canonicalSIEMRecordTypes = []string{
	models.SIEMRecordSignedClosure,
	models.SIEMRecordWORMLedger,
	models.SIEMRecordAuthClassSigning,
	models.SIEMRecordDispatchResult,
	models.SIEMRecordShieldEvent,
	models.SIEMRecordTwinProofVerdict,
	models.SIEMRecordIngestEvent,
	models.SIEMRecordSIEMConfigAudit,
}

var canonicalConsoleViews = []string{
	"VIEW1_RACE",
	"VIEW2_WARRANTS",
	"VIEW3_SHADOW",
	"VIEW4_CONTAINMENT",
	"VIEW5_AUDITOR",
}

// VerifySIEMConfigAuth enforces Item 3 & Acceptance:
//   - "Configuring a SIEM destination requires no additional device or authentication step and no dual key.
//      The dual key stays only at class signing and at release / dispatch."
//   - Rejects Estate Loader read tokens, intake tokens, auditor tokens, and Tetragon sensor tokens (HTTP 403).
//   - Accepts the standard Console operator session (no extra device/WebAuthn step, zero dual-key),
//     configured X-Warrant-Operator-Token, or local sandbox Console requests.
func (o *ControlPlaneOrchestrator) VerifySIEMConfigAuth(r *http.Request) (string, int, error) {
	if code, sepErr := o.RejectEstateReadCredentialOnMutation(r); sepErr != nil {
		return "", code, sepErr
	}
	if strings.TrimSpace(r.Header.Get("X-Warrant-Intake-Token")) != "" {
		return "", http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: X-Warrant-Intake-Token cannot configure SIEM destinations")
	}

	bearer := ""
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		bearer = strings.TrimSpace(auth[7:])
	}
	opHdr := strings.TrimSpace(r.Header.Get("X-Warrant-Operator-Token"))
	for _, cand := range []string{bearer, opHdr} {
		if cand == "" {
			continue
		}
		if strings.HasPrefix(cand, "g1aud_") || strings.HasPrefix(cand, "g1tet_") {
			return "", http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: auditor and sensor tokens cannot configure SIEM destinations")
		}
		if o.intakeToken != "" && subtle.ConstantTimeCompare([]byte(cand), []byte(o.intakeToken)) == 1 {
			return "", http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: WARRANT_INTAKE_TOKEN cannot configure SIEM destinations")
		}
	}

	// 1. Standard logged-in Console session (zero extra device step, zero dual-key)
	if sess, ok := o.ensureConsoleAuth().currentPrincipal(r); ok && sess != nil {
		if strings.EqualFold(sess.Role, "AUDITOR") {
			return "", http.StatusForbidden, fmt.Errorf("AUDITOR_SESSION_READ_ONLY: 3PAO auditor sessions cannot mutate SIEM destinations")
		}
		return sess.Email, http.StatusOK, nil
	}

	// 2. Programmatic operator token (when explicitly configured)
	for _, cand := range []string{opHdr, bearer} {
		if cand != "" && o.operatorToken != "" && subtle.ConstantTimeCompare([]byte(cand), []byte(o.operatorToken)) == 1 {
			return "operator-token", http.StatusOK, nil
		}
	}

	// 3. Sandbox / clean-room evaluation mode with no static operator token configured
	if !o.IsProductionOrLivePosture(r.Context()) && o.operatorToken == "" {
		return "console-sandbox-operator", http.StatusOK, nil
	}

	return "", http.StatusUnauthorized, fmt.Errorf("CONSOLE_SESSION_REQUIRED: sign in to the Warrant Console (no dual-key or extra device required)")
}

func rejectRawSecretFieldsInSIEMPayload(raw []byte) error {
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil
	}
	forbidden := map[string]bool{
		"secret":        true,
		"raw_secret":    true,
		"token":         true,
		"api_key":       true,
		"apikey":        true,
		"password":      true,
		"passphrase":    true,
		"client_secret": true,
		"private_key":   true,
	}
	var walk func(m map[string]any) error
	walk = func(m map[string]any) error {
		for k, v := range m {
			lk := strings.ToLower(strings.TrimSpace(k))
			if forbidden[lk] {
				return fmt.Errorf("RAW_SECRET_FORBIDDEN_CREDENTIAL_REF_REQUIRED: field %q is prohibited; supply only credential_ref URI (e.g. env://VAR or file:///run/secrets/name)", k)
			}
			if sub, ok := v.(map[string]any); ok {
				if err := walk(sub); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(top)
}

type siemDestinationUpsertPayload struct {
	DestinationID   string            `json:"destination_id,omitempty"`
	DisplayName     string            `json:"display_name"`
	SIEMVendor      string            `json:"siem_vendor"`
	Endpoint        string            `json:"endpoint"`
	CredentialRef   string            `json:"credential_ref"`
	Format          string            `json:"format"`
	VendorOptions   map[string]string `json:"vendor_options,omitempty"`
	RecordTypes     []string          `json:"record_types"`
	BatchSize       int               `json:"batch_size"`
	ScheduleSeconds int               `json:"schedule_seconds"`
	Enabled         *bool             `json:"enabled,omitempty"`
	ConsoleViews    []string          `json:"console_views"`
}

func (o *ControlPlaneOrchestrator) validateAndNormalizeSIEMPayload(in siemDestinationUpsertPayload, existingID string) (*models.SIEMDestination, error) {
	if o.SIEMShipper == nil {
		return nil, fmt.Errorf("SIEM shipper not initialized")
	}
	sender, err := o.SIEMShipper.Registry().Get(in.SIEMVendor)
	if err != nil {
		return nil, err
	}
	desc := sender.Descriptor()

	parsedRef, err := siem.ParseAndValidateCredentialRef(in.CredentialRef)
	if err != nil {
		return nil, err
	}

	ep := strings.TrimSpace(in.Endpoint)
	if ep == "" {
		return nil, fmt.Errorf("INVALID_SIEM_ENDPOINT: endpoint is required")
	}

	fmtVal := strings.ToUpper(strings.TrimSpace(in.Format))
	if fmtVal == "" {
		fmtVal = desc.DefaultFormat
	}
	fmtAllowed := false
	for _, sup := range desc.SupportedFormats {
		if sup == fmtVal {
			fmtAllowed = true
			break
		}
	}
	if !fmtAllowed {
		return nil, fmt.Errorf("UNSUPPORTED_SIEM_FORMAT: %s does not support format %q (supported: %v)", desc.VendorID, fmtVal, desc.SupportedFormats)
	}

	validRecSet := map[string]bool{}
	for _, rt := range canonicalSIEMRecordTypes {
		validRecSet[rt] = true
	}
	var normTypes []string
	seenRT := map[string]bool{}
	for _, rt := range in.RecordTypes {
		u := strings.ToUpper(strings.TrimSpace(rt))
		if u == "" || seenRT[u] {
			continue
		}
		if !validRecSet[u] {
			return nil, fmt.Errorf("INVALID_SIEM_RECORD_TYPE: %q", rt)
		}
		seenRT[u] = true
		normTypes = append(normTypes, u)
	}
	if len(normTypes) == 0 {
		normTypes = append([]string{}, canonicalSIEMRecordTypes...)
	}

	validViewSet := map[string]bool{}
	for _, cv := range canonicalConsoleViews {
		validViewSet[cv] = true
	}
	var normViews []string
	seenV := map[string]bool{}
	for _, cv := range in.ConsoleViews {
		u := strings.ToUpper(strings.TrimSpace(cv))
		if u == "" || seenV[u] {
			continue
		}
		if !validViewSet[u] {
			return nil, fmt.Errorf("INVALID_CONSOLE_VIEW: %q", cv)
		}
		seenV[u] = true
		normViews = append(normViews, u)
	}
	if len(normViews) == 0 {
		normViews = []string{"VIEW1_RACE", "VIEW4_CONTAINMENT", "VIEW5_AUDITOR"}
	}

	batchSize := in.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	} else if batchSize > 500 {
		return nil, fmt.Errorf("INVALID_BATCH_SIZE: batch_size must be between 1 and 500")
	}

	schedSec := in.ScheduleSeconds
	if schedSec <= 0 {
		schedSec = 10
	} else if schedSec > 3600 {
		return nil, fmt.Errorf("INVALID_SCHEDULE_SECONDS: schedule_seconds must be between 1 and 3600")
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	destID := strings.TrimSpace(existingID)
	if destID == "" {
		destID = strings.TrimSpace(in.DestinationID)
	}
	if destID == "" {
		destID = "siem-" + desc.VendorID + "-" + uuid.NewString()[:6]
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" {
		name = desc.DisplayName
	}

	cleanOpts := map[string]string{}
	for k, v := range in.VendorOptions {
		kt := strings.TrimSpace(k)
		vt := strings.TrimSpace(v)
		if kt != "" && vt != "" {
			cleanOpts[kt] = vt
		}
	}

	return &models.SIEMDestination{
		DestinationID:   destID,
		DisplayName:     name,
		SIEMVendor:      desc.VendorID,
		Endpoint:        ep,
		CredentialRef:   parsedRef.RawURI,
		Format:          fmtVal,
		VendorOptions:   cleanOpts,
		RecordTypes:     normTypes,
		BatchSize:       batchSize,
		ScheduleSeconds: schedSec,
		Enabled:         enabled,
		ConsoleViews:    normViews,
	}, nil
}

func (o *ControlPlaneOrchestrator) registerSIEMRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/siem/vendors", func(w http.ResponseWriter, _ *http.Request) {
		var vendors []models.SIEMVendorDescriptor
		if o.SIEMShipper != nil {
			vendors = o.SIEMShipper.Registry().Catalog()
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"vendors":       vendors,
			"record_types":  canonicalSIEMRecordTypes,
			"console_views": canonicalConsoleViews,
		})
	})

	mux.HandleFunc("GET /api/v1/siem/destinations", func(w http.ResponseWriter, r *http.Request) {
		dests, err := o.Store.ListSIEMDestinations(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, dests)
	})

	mux.HandleFunc("GET /api/v1/siem/audit", func(w http.ResponseWriter, r *http.Request) {
		records, err := o.Store.ListSIEMConfigAudit(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, records)
	})

	mux.HandleFunc("POST /api/v1/siem/destinations", func(w http.ResponseWriter, r *http.Request) {
		actor, code, authErr := o.VerifySIEMConfigAuth(r)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if secErr := rejectRawSecretFieldsInSIEMPayload(rawBody); secErr != nil {
			writeAPIError(w, http.StatusBadRequest, secErr)
			return
		}
		var in siemDestinationUpsertPayload
		if err := decodeStrictJSONBytes(rawBody, &in); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		dest, err := o.validateAndNormalizeSIEMPayload(in, "")
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		auditRec, err := o.Store.UpsertSIEMDestinationWithAudit(r.Context(), dest, "CREATE_DESTINATION", actor)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		saved, _ := o.Store.GetSIEMDestination(r.Context(), dest.DestinationID)
		if saved == nil {
			saved = dest
		}
		o.Broker.Broadcast("SIEM_DESTINATION_UPDATED", saved)
		writeAPIJSON(w, http.StatusCreated, map[string]any{
			"destination": saved,
			"audit":       auditRec,
		})
	})

	mux.HandleFunc("PUT /api/v1/siem/destinations/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, code, authErr := o.VerifySIEMConfigAuth(r)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		existing, err := o.Store.GetSIEMDestination(r.Context(), id)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, err)
			return
		}
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if secErr := rejectRawSecretFieldsInSIEMPayload(rawBody); secErr != nil {
			writeAPIError(w, http.StatusBadRequest, secErr)
			return
		}
		var in siemDestinationUpsertPayload
		if err := decodeStrictJSONBytes(rawBody, &in); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		dest, err := o.validateAndNormalizeSIEMPayload(in, id)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		dest.CreatedAt = existing.CreatedAt
		dest.CreatedBy = existing.CreatedBy

		auditAction := "UPDATE_DESTINATION"
		if existing.Enabled != dest.Enabled {
			auditAction = "TOGGLE_DESTINATION"
		}
		auditRec, err := o.Store.UpsertSIEMDestinationWithAudit(r.Context(), dest, auditAction, actor)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		saved, _ := o.Store.GetSIEMDestination(r.Context(), id)
		if saved == nil {
			saved = dest
		}
		o.Broker.Broadcast("SIEM_DESTINATION_UPDATED", saved)
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"destination": saved,
			"audit":       auditRec,
		})
	})

	mux.HandleFunc("DELETE /api/v1/siem/destinations/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, code, authErr := o.VerifySIEMConfigAuth(r)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		auditRec, err := o.Store.DeleteSIEMDestinationWithAudit(r.Context(), id, actor)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, err)
			return
		}
		o.Broker.Broadcast("SIEM_DESTINATION_DELETED", map[string]string{"destination_id": id})
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"deleted_id": id,
			"audit":      auditRec,
		})
	})

	mux.HandleFunc("POST /api/v1/siem/destinations/{id}/flush", func(w http.ResponseWriter, r *http.Request) {
		if _, code, authErr := o.VerifySIEMConfigAuth(r); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		res, err := o.SIEMShipper.FlushDestinationNow(r.Context(), id)
		if err != nil {
			if res != nil {
				writeAPIJSON(w, http.StatusUnprocessableEntity, map[string]any{
					"error":        err.Error(),
					"flush_result": res,
				})
				return
			}
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, res)
	})
}
