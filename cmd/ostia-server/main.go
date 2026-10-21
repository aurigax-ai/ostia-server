package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/server"
)

var version = "dev"

const (
	defaultConfig = "ostia-server.toml"
	configEnv     = "OSTIA_SERVER_CONFIG"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ostia-server:", err)
		os.Exit(1)
	}
}

func defaultConfigPath() string {
	if v := os.Getenv(configEnv); v != "" {
		return v
	}
	return defaultConfig
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Println(version)
			return nil
		case "admin":
			return admin(args[1:])
		case "help", "-h", "--help":
			fmt.Print(usage)
			return nil
		}
	}
	flags := flag.NewFlagSet("ostia-server", flag.ContinueOnError)
	path := flags.String("config", defaultConfigPath(), "path to the TOML config file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	setupLogging(cfg.LogLevel)
	srv, err := server.New(cfg, server.Options{})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			if err := srv.ReloadCertificates(); err != nil {
				slog.Error("reload certificates", "err", err)
				continue
			}
			slog.Info("certificates reloaded")
		}
	}()
	slog.Info("ostia-server starting", "version", version, "relay", cfg.RelayEnabled(), "publish", cfg.PublishEnabled(), "sync", cfg.SyncEnabled(), "push", cfg.Modules.Push)
	return srv.Run(ctx)
}

func setupLogging(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

const usage = `ostia-server [-config file]            run the server
ostia-server admin [-config file] <command>
    invite [-ttl 168h]                 print a one-time sign-in code that creates a new account
    accounts                           list accounts
    reports                            list reported shares
    takedown <share-id>                disable a share and delete its content
    disable-publish <account-id>       stop an account from publishing
    enable-publish <account-id>        allow an account to publish again
    delete-account <account-id>        remove an account and everything it stored
ostia-server version
`

var errUsage = errors.New("usage: ostia-server admin [-config file] <command> (see ostia-server help)")

func admin(args []string) error {
	flags := flag.NewFlagSet("admin", flag.ContinueOnError)
	path := flags.String("config", defaultConfigPath(), "path to the TOML config file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	rest := flags.Args()
	if len(rest) == 0 {
		return errUsage
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	a, err := server.OpenAdmin(cfg)
	if err != nil {
		return err
	}
	defer a.Close()
	ctx := context.Background()
	command, operands := rest[0], rest[1:]
	switch command {
	case "invite":
		sub := flag.NewFlagSet("invite", flag.ContinueOnError)
		ttl := sub.Duration("ttl", cfg.Auth.InviteTTL.Std(), "how long the code stays valid")
		if err := sub.Parse(operands); err != nil {
			return err
		}
		code, expires, err := a.Invite(ctx, *ttl)
		if err != nil {
			return err
		}
		fmt.Printf("%s\nexpires %s\n", code, time.UnixMilli(expires).UTC().Format(time.RFC3339))
		return nil
	case "accounts":
		accounts, err := a.Accounts(ctx)
		if err != nil {
			return err
		}
		for _, acct := range accounts {
			fmt.Printf("%s\t%s\tcreated %s\tpublish-disabled=%t\n", acct.ID, acct.Provider, time.UnixMilli(acct.CreatedAt).UTC().Format(time.RFC3339), acct.PublishDisabled)
		}
		return nil
	case "reports":
		reports, err := a.Reports(ctx)
		if err != nil {
			return err
		}
		for _, r := range reports {
			fmt.Printf("%s\treports=%d\tlatest %s\taccount=%s\tremoved=%t\n", r.ShareID, r.Reports, time.UnixMilli(r.Latest).UTC().Format(time.RFC3339), r.AccountID, r.Removed)
		}
		return nil
	case "takedown", "disable-publish", "enable-publish", "delete-account":
		if len(operands) != 1 {
			return fmt.Errorf("%s needs exactly one id", command)
		}
		return idCommand(ctx, a, command, operands[0])
	}
	return fmt.Errorf("unknown admin command %q\n%s", command, usage)
}

func idCommand(ctx context.Context, a *server.Admin, command, id string) error {
	switch command {
	case "takedown":
		return a.TakeDown(ctx, id)
	case "disable-publish":
		return a.SetPublishDisabled(ctx, id, true)
	case "enable-publish":
		return a.SetPublishDisabled(ctx, id, false)
	default:
		return a.DeleteAccount(ctx, id)
	}
}
