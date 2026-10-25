package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/adminui"
	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/blob"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/publish"
	"github.com/aurigax-ai/ostia-server/internal/serverkey"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

type Admin struct {
	DB      *store.DB
	Auth    *auth.Service
	Publish *publish.Service
	Cfg     config.Config
}

func OpenAdmin(cfg config.Config) (*Admin, error) {
	db, err := store.Open(filepath.Join(cfg.DataDir, "ostia.sqlite"), cfg.Storage.SQLiteJournal, time.Now)
	if err != nil {
		return nil, err
	}
	blobs, err := blob.NewDisk(filepath.Join(cfg.DataDir, "blobs"))
	if err != nil {
		return nil, err
	}
	key, err := serverkey.Load(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	authSvc := &auth.Service{DB: db, Blobs: blobs, Key: key, Cfg: cfg.Auth, Now: time.Now}
	return &Admin{
		DB:      db,
		Auth:    authSvc,
		Publish: &publish.Service{DB: db, Blobs: blobs, Auth: authSvc, Cfg: cfg.Publish, Now: time.Now},
		Cfg:     cfg,
	}, nil
}

func (a *Admin) Close() error { return a.DB.Close() }

func (a *Admin) Invite(ctx context.Context, ttl time.Duration) (code string, expiresAt int64, err error) {
	if max := a.Cfg.Auth.InviteTTL.Std(); ttl > max {
		return "", 0, fmt.Errorf("an invite code may live at most auth.invite_ttl (%s), not %s", max, ttl)
	}
	return a.Auth.CreateInvite(ctx, ttl)
}

func (a *Admin) SetupCode(ctx context.Context) (string, error) {
	if !a.Cfg.Admin.Enabled {
		return "", errors.New("the admin web UI is off; set admin.enabled = true in the config")
	}
	code, err := adminui.IssueSetupCode(ctx, a.DB)
	if errors.Is(err, store.ErrAdminExists) {
		return "", errors.New("an admin already exists; run admin reset first to start over")
	}
	return code, err
}

func (a *Admin) ResetAdmins(ctx context.Context) (admins, sessions int64, err error) {
	if admins, sessions, err = a.DB.ResetAdmins(ctx); err != nil {
		return 0, 0, err
	}
	return admins, sessions, a.DB.AddAudit(ctx, "cli", "reset", fmt.Sprintf("%d admins, %d sessions", admins, sessions))
}

func (a *Admin) LogoutAll(ctx context.Context) (int64, error) {
	n, err := a.DB.DeleteAdminSessions(ctx)
	if err != nil {
		return 0, err
	}
	return n, a.DB.AddAudit(ctx, "cli", "logout-all", strconv.FormatInt(n, 10))
}

func (a *Admin) Audit(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	return a.DB.Audit(ctx, limit)
}

func (a *Admin) Accounts(ctx context.Context) ([]store.Account, error) { return a.DB.Accounts(ctx) }

func (a *Admin) Reports(ctx context.Context) ([]store.ReportSummary, error) {
	return a.DB.ReportSummaries(ctx)
}

func (a *Admin) TakeDown(ctx context.Context, shareID string) error {
	return a.Publish.TakeDown(ctx, shareID)
}

func (a *Admin) SetPublishDisabled(ctx context.Context, accountID string, disabled bool) error {
	return a.DB.SetPublishDisabled(ctx, accountID, disabled)
}

func (a *Admin) DeleteAccount(ctx context.Context, accountID string) error {
	return a.Auth.DeleteAccount(ctx, accountID)
}
