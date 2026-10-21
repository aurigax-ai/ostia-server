package server

import (
	"context"
	"path/filepath"
	"time"

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
	db, err := store.Open(filepath.Join(cfg.DataDir, "ostia.sqlite"), time.Now)
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
	return a.Auth.CreateInvite(ctx, "", ttl)
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
	return a.Auth.DeleteAccount(ctx, accountID, nil)
}
