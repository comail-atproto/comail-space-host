package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-pds-lab/internal/mailboxviewer"
)

type options struct {
	Listen              string
	HappyViewOrigin     string
	HappyViewBasePath   string
	HappyViewPublicHost string
	DID                 string
	SpaceKey            string
	LoginPath           string
	PublicOrigin        string
	CookiePath          string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "comail-mailbox-viewer:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("comail-mailbox-viewer", flag.ContinueOnError)
	opts := options{}
	flags.StringVar(&opts.Listen, "listen", "127.0.0.1:39093", "exact IPv4 loopback listener")
	flags.StringVar(&opts.HappyViewOrigin, "happyview-origin", "http://127.0.0.1:39090", "isolated HappyView loopback origin")
	flags.StringVar(&opts.HappyViewBasePath, "happyview-base-path", "/comail-pds-lab", "HappyView path prefix")
	flags.StringVar(&opts.HappyViewPublicHost, "happyview-public-host", "little-mac.lobster-hake.ts.net", "exact HappyView virtual host")
	flags.StringVar(&opts.DID, "did", "", "exact mailbox owner DID")
	flags.StringVar(&opts.SpaceKey, "space-key", "default", "exact mailbox space key")
	flags.StringVar(&opts.LoginPath, "login-path", "/comail-pds-lab/login/", "same-origin HappyView login path")
	flags.StringVar(&opts.PublicOrigin, "public-origin", "https://little-mac.lobster-hake.ts.net", "exact browser-facing HTTPS origin")
	flags.StringVar(&opts.CookiePath, "cookie-path", "/comail-pds-mailbox/", "exact browser-facing viewer path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateOptions(opts); err != nil {
		return err
	}
	loader, err := mailboxviewer.NewHappyViewLoader(mailboxviewer.HappyViewConfig{
		Origin: opts.HappyViewOrigin, BasePath: opts.HappyViewBasePath, PublicHost: opts.HappyViewPublicHost, DID: opts.DID, SpaceKey: opts.SpaceKey,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", opts.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler: mailboxviewer.NewMutableHandler(loader, mailboxviewer.MutableConfig{
			LoginPath: opts.LoginPath, PublicOrigin: opts.PublicOrigin, CookiePath: opts.CookiePath,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	fmt.Printf("Private mailbox state lab listening on http://%s\n", opts.Listen)
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func validateOptions(opts options) error {
	host, port, err := net.SplitHostPort(opts.Listen)
	if err != nil || host != "127.0.0.1" || port == "" {
		return errors.New("listener must use exact IPv4 loopback")
	}
	if _, err := syntax.ParseDID(opts.DID); err != nil {
		return errors.New("an exact account DID is required")
	}
	if opts.SpaceKey == "" || strings.ContainsAny(opts.SpaceKey, "/?#") || strings.Contains(opts.SpaceKey, "..") {
		return errors.New("an exact mailbox space key is required")
	}
	if opts.HappyViewPublicHost == "" || strings.ContainsAny(opts.HappyViewPublicHost, "/ :?#@") {
		return errors.New("an exact HappyView public host is required")
	}
	if !strings.HasPrefix(opts.LoginPath, "/") || strings.HasPrefix(opts.LoginPath, "//") || strings.Contains(opts.LoginPath, "..") {
		return errors.New("login path must be a safe same-origin path")
	}
	publicOrigin, err := url.Parse(opts.PublicOrigin)
	if err != nil || publicOrigin.Scheme != "https" || publicOrigin.Hostname() == "" || publicOrigin.User != nil || publicOrigin.Path != "" || publicOrigin.RawQuery != "" || publicOrigin.Fragment != "" {
		return errors.New("public origin must be an exact HTTPS origin")
	}
	if !strings.HasPrefix(opts.CookiePath, "/") || !strings.HasSuffix(opts.CookiePath, "/") || strings.Contains(opts.CookiePath, "..") {
		return errors.New("cookie path must be an exact absolute directory path")
	}
	return nil
}
