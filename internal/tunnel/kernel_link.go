package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/network"
)

// Kernel link ownership.
//
// The kernel does not apply IFLA_IFALIAS on RTM_NEWLINK create, so an alias
// cannot mark a link atomically. The only caller-chosen attribute stored
// atomically with the link is its ifindex: the link is created with a random
// requested index under NLM_F_CREATE|NLM_F_EXCL, and that index is written to
// a dedicated intent journal before the create request is sent. The journal
// lives outside tunnel-states so older recovery code never sees it.
//
// Assumptions: create, inspect and delete run in one network namespace; a
// root actor that deletes our link and recreates one with the same random
// index, name and kind between the inspection and RTM_DELLINK is outside the
// threat model (netlink has no compare-and-delete).

const (
	kernelLinkIntentsDir    = "kernel-link-intents"
	kernelLinkIntentVersion = 1
	kernelLinkKind          = "wireguard"
	kernelLinkCreateTries   = 4
	kernelLinkIndexMin      = 1 << 24
	kernelLinkIndexMax      = 1<<31 - 1
)

var (
	errKernelLinkExists   = errors.New("kernel link already exists")
	errKernelLinkNotFound = errors.New("kernel link not found")
	errKernelLinkNotOwned = errors.New("kernel link at the recorded index is not owned by WireGuide")
	errKernelLinkBusy     = errors.New("another WireGuide process is creating this kernel interface")
)

type kernelLink struct {
	Index int32
	Name  string
	Kind  string
	Alias string
}

// kernelLinkBackend is the minimal rtnetlink surface used for ownership.
// CreateWireGuard must send NLM_F_CREATE|NLM_F_EXCL with the requested index
// and wrap EEXIST as errKernelLinkExists; DeleteIndex wraps ENODEV as
// errKernelLinkNotFound.
type kernelLinkBackend interface {
	LinkByIndex(index int32) (kernelLink, bool, error)
	LinkByName(name string) (kernelLink, bool, error)
	CreateWireGuard(name string, index int32) error
	SetAlias(index int32, alias string) error
	DeleteIndex(index int32) error
}

var kernelLinkBackendFactory = defaultKernelLinkBackend

// kernelLinkOwner is implemented by kernel engines whose link is identified
// by ifindex.
type kernelLinkOwner interface {
	kernelLinkIndex() int32
	commitKernelLinkIntent() error
	releaseKernelLink() error
}

const kernelOwnershipAliasPrefix = "wireguide:"

var errKernelInterfaceConflict = errors.New("kernel interface name is already in use")

func kernelInterfaceError(name string, err error) error {
	msg := err.Error()
	hint := ""
	switch {
	case strings.Contains(msg, "executable file not found"):
		hint = " (install iproute2)"
	case strings.Contains(msg, "Operation not supported"),
		strings.Contains(msg, "operation not supported"),
		strings.Contains(msg, "Protocol not supported"),
		strings.Contains(msg, "protocol not supported"),
		strings.Contains(msg, "Unknown device type"):
		hint = " (the WireGuard kernel module is unavailable; run 'modprobe wireguard' or install the WireGuard module package for your kernel)"
	}
	return fmt.Errorf("creating WireGuard kernel interface %q: %w%s", name, err, hint)
}

func kernelOwnershipAlias(tunnel string) string { return kernelOwnershipAliasPrefix + tunnel }

func randomKernelLinkIndex() int32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	span := uint32(kernelLinkIndexMax - kernelLinkIndexMin + 1)
	return int32(kernelLinkIndexMin + binary.LittleEndian.Uint32(b[:])%span)
}

var newKernelLinkIndex = randomKernelLinkIndex

// deleteOwnedKernelLink deletes the link at index only when its identity
// matches. An absent link is success. A mismatch returns
// errKernelLinkNotOwned and never mutates the device.
func deleteOwnedKernelLink(b kernelLinkBackend, index int32, name, alias string, allowEmptyAlias bool) error {
	if index <= 0 {
		return fmt.Errorf("invalid kernel link index %d", index)
	}
	link, found, err := b.LinkByIndex(index)
	if err != nil {
		return fmt.Errorf("inspecting kernel link %d: %w", index, err)
	}
	if !found {
		return nil
	}
	if link.Name != name || link.Kind != kernelLinkKind || !(link.Alias == alias || (allowEmptyAlias && link.Alias == "")) {
		return fmt.Errorf("%w: index %d is %q kind %q alias %q, want %q kind %q alias %q",
			errKernelLinkNotOwned, index, link.Name, link.Kind, link.Alias, name, kernelLinkKind, alias)
	}
	if err := b.DeleteIndex(index); err != nil && !errors.Is(err, errKernelLinkNotFound) {
		return fmt.Errorf("deleting kernel link %q at index %d: %w", name, index, err)
	}
	return nil
}

type kernelLinkIntent struct {
	Version     int    `json:"version"`
	Tunnel      string `json:"tunnel"`
	IfName      string `json:"ifname"`
	IfIndex     int32  `json:"ifindex"`
	Token       string `json:"token"`
	CreatedUnix int64  `json:"created_unix"`
}

func (in *kernelLinkIntent) valid() bool {
	return in.Version == kernelLinkIntentVersion && in.IfName != "" && in.IfIndex > 0 && in.Token != ""
}

func kernelIntentBase(tunnel string) string {
	return strings.TrimSuffix(stateFileName(tunnel), ".json")
}

func kernelIntentPaths(dataDir, base string) (intent, lock string) {
	dir := filepath.Join(dataDir, kernelLinkIntentsDir)
	return filepath.Join(dir, base+".json"), filepath.Join(dir, base+".lock")
}

func readKernelIntent(path string) (*kernelLinkIntent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in kernelLinkIntent
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	if !in.valid() {
		return nil, fmt.Errorf("invalid kernel link intent %s", filepath.Base(path))
	}
	return &in, nil
}

func writeKernelIntent(path string, in *kernelLinkIntent) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data, 0o600)
}

// removeKernelIntent deletes the intent only when it still carries token.
func removeKernelIntent(path, token string) error {
	cur, err := readKernelIntent(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil && cur.Token != token {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func quarantineKernelIntent(path string, cause error) {
	slog.Warn("unreadable kernel link intent, preserving as .corrupt", "file", path, "error", cause)
	if err := os.Rename(path, path+".corrupt"); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("could not preserve corrupt kernel link intent", "file", path, "error", err)
	}
}

// resolveKernelIntent removes the link recorded by an intent if it is still
// ours. The caller holds the intent lock. The intent is removed only when
// the link is provably gone.
func resolveKernelIntent(b kernelLinkBackend, path string, in *kernelLinkIntent) error {
	err := deleteOwnedKernelLink(b, in.IfIndex, in.IfName, kernelOwnershipAlias(in.Tunnel), true)
	if err != nil {
		return err
	}
	return removeKernelIntent(path, in.Token)
}

// recoverKernelLinkIntents resolves intents left by a crashed creation. It
// touches nothing except the recorded link: no firewall, DNS or routes.
func recoverKernelLinkIntents(dataDir string) {
	if dataDir == "" {
		return
	}
	dir := filepath.Join(dataDir, kernelLinkIntentsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("kernel link recovery: reading intents failed", "error", err)
		}
		return
	}
	var backend kernelLinkBackend
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".json")
		intentPath, lockPath := kernelIntentPaths(dataDir, base)
		lock, err := tryLockKernelIntent(lockPath)
		if err != nil {
			slog.Warn("kernel link recovery: skipping intent", "intent", e.Name(), "error", err)
			continue
		}
		func() {
			defer lock.unlock()
			in, err := readKernelIntent(intentPath)
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			if err != nil {
				quarantineKernelIntent(intentPath, err)
				return
			}
			if backend == nil {
				if backend, err = kernelLinkBackendFactory(); err != nil {
					backend = nil
					slog.Warn("kernel link recovery: netlink unavailable; keeping intent", "intent", e.Name(), "error", err)
					return
				}
			}
			if err := resolveKernelIntent(backend, intentPath, in); err != nil {
				slog.Warn("kernel link recovery: keeping intent", "tunnel", in.Tunnel, "interface", in.IfName, "index", in.IfIndex, "intent", intentPath, "error", err)
				return
			}
			slog.Info("kernel link recovery: resolved interrupted creation", "tunnel", in.Tunnel, "interface", in.IfName, "index", in.IfIndex)
		}()
	}
}

// kernelLinkRequest describes one kernel link creation. dataDir may be empty
// (standalone NewEngineWithBackend); creation then still uses a random index
// and identity-checked deletion, but there is no durable intent, so a crash
// between RTM_NEWLINK and the caller's own state save leaves an orphan.
type kernelLinkRequest struct {
	backend   kernelLinkBackend
	dataDir   string
	tunnel    string
	name      string
	prepare   func() error
	configure func() error
}

type kernelLinkHandle struct {
	mu         sync.Mutex
	backend    kernelLinkBackend
	tunnel     string
	name       string
	index      int32
	intentPath string
	token      string
	intentHeld bool
	lock       *kernelIntentLock
	aliasSet   bool
	gone       bool
}

func createKernelLink(req kernelLinkRequest) (*kernelLinkHandle, error) {
	h := &kernelLinkHandle{backend: req.backend, tunnel: req.tunnel, name: req.name}
	if req.dataDir != "" {
		base := kernelIntentBase(req.tunnel)
		intentPath, lockPath := kernelIntentPaths(req.dataDir, base)
		if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
			return nil, fmt.Errorf("creating kernel link intent directory: %w", err)
		}
		lock, err := tryLockKernelIntent(lockPath)
		if err != nil {
			return nil, err
		}
		h.lock, h.intentPath = lock, intentPath
		if prev, err := readKernelIntent(intentPath); err == nil {
			if err := resolveKernelIntent(req.backend, intentPath, prev); err != nil {
				h.unlock()
				return nil, fmt.Errorf("an interrupted kernel interface creation for %q is unresolved (intent %s): %w", req.tunnel, intentPath, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			quarantineKernelIntent(intentPath, err)
		}
	}
	if req.prepare != nil {
		if err := req.prepare(); err != nil {
			h.unlock()
			return nil, err
		}
	}

	created := false
	for attempt := 0; attempt < kernelLinkCreateTries && !created; attempt++ {
		h.index = newKernelLinkIndex()
		h.token = rand.Text()
		if h.intentPath != "" {
			in := &kernelLinkIntent{Version: kernelLinkIntentVersion, Tunnel: req.tunnel, IfName: req.name, IfIndex: h.index, Token: h.token, CreatedUnix: time.Now().Unix()}
			if err := writeKernelIntent(h.intentPath, in); err != nil {
				h.unlock()
				return nil, fmt.Errorf("persisting kernel link intent: %w", err)
			}
			h.intentHeld = true
		}
		err := req.backend.CreateWireGuard(req.name, h.index)
		switch {
		case err == nil:
			created = true
		case errors.Is(err, errKernelLinkExists):
			_, nameTaken, lookupErr := req.backend.LinkByName(req.name)
			if lookupErr != nil {
				return nil, h.dropIntent(kernelInterfaceError(req.name, errors.Join(err, lookupErr)))
			}
			if nameTaken {
				return nil, h.dropIntent(fmt.Errorf("%w: %q appeared while creating it; it was left untouched", errKernelInterfaceConflict, req.name))
			}
		default:
			return nil, h.abort(kernelInterfaceError(req.name, err))
		}
	}
	if !created {
		return nil, h.dropIntent(fmt.Errorf("creating WireGuard kernel interface %q: no free random ifindex after %d attempts", req.name, kernelLinkCreateTries))
	}

	if err := req.backend.SetAlias(h.index, kernelOwnershipAlias(req.tunnel)); err != nil {
		return nil, h.abort(fmt.Errorf("marking kernel interface %q as WireGuide-owned: %w", req.name, err))
	}
	h.aliasSet = true
	link, found, err := req.backend.LinkByIndex(h.index)
	if err != nil || !found || link.Name != req.name || link.Kind != kernelLinkKind || link.Alias != kernelOwnershipAlias(req.tunnel) {
		if err == nil {
			err = fmt.Errorf("kernel link %d is %+v after creation", h.index, link)
		}
		return nil, h.abort(fmt.Errorf("verifying kernel interface %q: %w", req.name, err))
	}
	if req.configure != nil {
		if err := req.configure(); err != nil {
			return nil, h.abort(err)
		}
	}
	return h, nil
}

// abort releases a failed creation and returns primary joined with any
// cleanup failure. The intent is kept when the link cannot be proven gone.
func (h *kernelLinkHandle) abort(primary error) error {
	if err := h.releaseKernelLink(); err != nil {
		return errors.Join(primary, err)
	}
	return primary
}

// dropIntent ends a creation that the kernel definitively rejected with
// EEXIST. Nothing was created, so no device is inspected or deleted.
func (h *kernelLinkHandle) dropIntent(primary error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gone = true
	if h.intentHeld {
		if err := removeKernelIntent(h.intentPath, h.token); err != nil {
			primary = errors.Join(primary, fmt.Errorf("removing kernel link intent: %w", err))
		} else {
			h.intentHeld = false
		}
	}
	h.unlock()
	return primary
}

func (h *kernelLinkHandle) unlock() {
	if h.lock != nil {
		h.lock.unlock()
		h.lock = nil
	}
}

func (h *kernelLinkHandle) kernelLinkIndex() int32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.index
}

// commitKernelLinkIntent hands ownership to ActiveTunnelState. Call only
// after a state carrying the index was saved. The lock stays held if the
// intent cannot be removed, so no other helper treats the live link as stale.
func (h *kernelLinkHandle) commitKernelLinkIntent() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.intentHeld {
		h.unlock()
		return nil
	}
	if err := removeKernelIntent(h.intentPath, h.token); err != nil {
		return err
	}
	h.intentHeld = false
	h.unlock()
	return nil
}

// releaseKernelLink deletes the link by index after an identity check. It
// is idempotent and keeps the intent when deletion fails.
func (h *kernelLinkHandle) releaseKernelLink() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.gone && h.index > 0 {
		err := deleteOwnedKernelLink(h.backend, h.index, h.name, kernelOwnershipAlias(h.tunnel), !h.aliasSet)
		if errors.Is(err, errKernelLinkNotOwned) {
			slog.Warn("kernel link was replaced; leaving the foreign device untouched", "interface", h.name, "index", h.index, "error", err)
			err = nil
		}
		if err != nil {
			h.unlock()
			return err
		}
		h.gone = true
	}
	if h.intentHeld {
		if err := removeKernelIntent(h.intentPath, h.token); err != nil {
			h.unlock()
			return fmt.Errorf("removing kernel link intent: %w", err)
		}
		h.intentHeld = false
	}
	h.unlock()
	return nil
}

func kernelLinkGuardFor(owner kernelLinkOwner, iface string) network.LinkCleanupGuard {
	return func(_, name string) (bool, error) {
		if name != iface {
			return false, nil
		}
		return true, owner.releaseKernelLink()
	}
}

// kernelRecoveryLinkGuard deletes, by index, links recorded in recovery
// journals for iface. Journals without kernel_ifindex keep the legacy
// name-based cleanup.
func kernelRecoveryLinkGuard(dataDir, iface string) (bool, error) {
	if dataDir == "" || iface == "" {
		return false, nil
	}
	var owned []*ActiveTunnelState
	for _, st := range LoadActiveState(dataDir) {
		if st.KernelIfindex > 0 && st.InterfaceName == iface {
			owned = append(owned, st)
		}
	}
	if len(owned) == 0 {
		return false, nil
	}
	backend, err := kernelLinkBackendFactory()
	if err != nil {
		return true, fmt.Errorf("kernel link recovery for %q: %w", iface, err)
	}
	var errs []error
	for _, st := range owned {
		err := deleteOwnedKernelLink(backend, st.KernelIfindex, iface, kernelOwnershipAlias(st.TunnelName), false)
		if errors.Is(err, errKernelLinkNotOwned) {
			slog.Warn("crash recovery: recorded kernel link is not ours; leaving it untouched", "tunnel", st.TunnelName, "interface", iface, "error", err)
			err = nil
		}
		errs = append(errs, err)
	}
	return true, errors.Join(errs...)
}

func installKernelLinkGuard(mgr network.NetworkManager) {
	if setter, ok := mgr.(network.LinkCleanupGuardSetter); ok {
		setter.SetLinkCleanupGuard(kernelRecoveryLinkGuard)
	}
}
