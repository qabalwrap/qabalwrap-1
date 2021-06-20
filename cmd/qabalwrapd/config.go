package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	identnormalize "github.com/nangantata/go-identnormalize"
	yaml "gopkg.in/yaml.v3"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type configuration struct {
	StateFolder   string `yaml:"state-folder"`
	MessageSwitch struct {
		TextIdent string `yaml:"ident"`
		DN        struct {
			Country      string `yaml:"c"`
			Organization string `yaml:"o"`
		} `yaml:"dn"`
		PrimaryEnablement bool `yaml:"primary"`
	} `yaml:"message-switch"`
	HTTPServers []*struct {
		TextIdent  string `yaml:"ident"`
		ListenAddr string `yaml:"listen"`
	} `yaml:"http-servers"`
	AccessProviders struct {
		HTTPServers []*struct {
			TextIdent       string `yaml:"ident"`
			LinkServerIdent string `yaml:"attach-to"`
			HTTPHost        string `yaml:"http-host"`
			AccessChannels  []*struct {
				SharedSecretText  string `yaml:"shared-key"`
				MessageBufferSize int    `yaml:"buffer-size"`
			} `yaml:"channels"`
		} `yaml:"http-servers"`
		HTTPClients []*struct {
			TextIdent         string                                 `yaml:"ident"`
			SharedSecretText  string                                 `yaml:"shared-key"`
			MessageBufferSize int                                    `yaml:"buffer-size"`
			TargetServerURL   string                                 `yaml:"target-url"`
			HTTPHostOverride  string                                 `yaml:"host-override"`
			ChannelIndex      int                                    `yaml:"channel-index"`
			ExchangeMode      qabalwrap.HTTPClientAccessExchangeMode `yaml:"exchange-mode"`
			SkipTLSVerify     bool                                   `yaml:"skip-tls-verify"`
		} `yaml:"http-clients"`
	} `yaml:"access-providers"`
	ContentEdges []*struct {
		TextIdent               string `yaml:"ident"`
		LinkServerIdent         string `yaml:"attach-to"`
		HTTPHost                string `yaml:"http-host"`
		FetcherIdent            string `yaml:"fetch-from"`
		MaxTransferSessionCount int    `yaml:"max-transfer-links"`
	} `yaml:"content-edges"`
	ContentFetchers []*struct {
		TextIdent            string `yaml:"ident"`
		TargetContentURL     string `yaml:"target-url"`
		HTTPHostOverride     string `yaml:"host-override"`
		MaxFetchSessionCount int    `yaml:"max-work-links"`
	} `yaml:"content-fetchers"`
}

func (cfg *configuration) setupContentHTTPFetchService(ctx context.Context, msgSwitch *qabalwrap.MessageSwitch) (err error) {
	for _, opt := range cfg.ContentFetchers {
		var targetContentURL *url.URL
		if targetContentURL, err = url.Parse(opt.TargetContentURL); nil != err {
			return
		}
		contentFetcher := qabalwrap.NewHTTPContentFetcher(targetContentURL, opt.HTTPHostOverride, opt.MaxFetchSessionCount)
		msgSwitch.AddContentFetchProvider(opt.TextIdent, contentFetcher)
	}
	return
}

func (cfg *configuration) setupContentHTTPEdgeService(ctx context.Context, msgSwitch *qabalwrap.MessageSwitch, httpSrvs map[string]*qabalwrap.HTTPServerService) (err error) {
	for idx, opt := range cfg.ContentEdges {
		targetHTTPSrv := httpSrvs[opt.LinkServerIdent]
		if targetHTTPSrv == nil {
			err = fmt.Errorf("content edge cannot reach link target HTTP server service (index=%d, ident=%s): [%s]",
				idx, opt.TextIdent, opt.LinkServerIdent)
			return
		}
		contentEdge := qabalwrap.NewHTTPContentServeHandler(opt.FetcherIdent, opt.MaxTransferSessionCount)
		targetHTTPSrv.AddHostHandler(opt.HTTPHost, contentEdge)
		msgSwitch.AddContentEdgeProvider(opt.TextIdent, contentEdge)
	}
	return
}

func (cfg *configuration) setupAccessProviderHTTPServerService(ctx context.Context, msgSwitch *qabalwrap.MessageSwitch, httpSrvs map[string]*qabalwrap.HTTPServerService) (err error) {
	for idx, opt := range cfg.AccessProviders.HTTPServers {
		targetHTTPSrv := httpSrvs[opt.LinkServerIdent]
		if targetHTTPSrv == nil {
			err = fmt.Errorf("cannot reach link target HTTP server service (index=%d, ident=%s): [%s]",
				idx, opt.TextIdent, opt.LinkServerIdent)
			return
		}
		accessChannels := make([]*qabalwrap.HTTPServeAccessChannel, len(opt.AccessChannels))
		for chIdx, chOpt := range opt.AccessChannels {
			var chInst *qabalwrap.HTTPServeAccessChannel
			if chInst, err = qabalwrap.NewHTTPServeAccessChannel(ctx, chOpt.SharedSecretText, chOpt.MessageBufferSize); nil != err {
				log.Printf("ERROR: cannot create HTTP server access provider (channel=%d, index=%d, ident=%s): %v", chIdx, idx, opt.TextIdent, err)
				return
			}
			accessChannels[chIdx] = chInst
			msgSwitch.AddRelayProvider(chInst)
		}
		provider := qabalwrap.NewHTTPServeAccessProvider(accessChannels)
		targetHTTPSrv.AddHostHandler(opt.HTTPHost, provider)
		msgSwitch.AddAccessProviderService(opt.TextIdent, provider)
	}
	return
}

func (cfg *configuration) setupAccessProviderHTTPClientService(ctx context.Context, msgSwitch *qabalwrap.MessageSwitch) (err error) {
	for idx, opt := range cfg.AccessProviders.HTTPClients {
		var targetServerURL *url.URL
		if targetServerURL, err = url.Parse(opt.TargetServerURL); nil != err {
			log.Printf("ERROR: cannot parse URL of access HTTP server access provider (index=%d, ident=%s): %v", idx, opt.TextIdent, err)
			return
		}
		var provider *qabalwrap.HTTPClientAccessProvider
		if provider, err = qabalwrap.NewHTTPClientAccessProvider(ctx, opt.SharedSecretText, opt.MessageBufferSize, targetServerURL, opt.HTTPHostOverride, opt.ChannelIndex, opt.ExchangeMode, opt.SkipTLSVerify); nil != err {
			log.Printf("ERROR: cannot create HTTP client access provider (index=%d, ident=%s): %v", idx, opt.TextIdent, err)
			return
		}
		msgSwitch.AddRelayProvider(provider)
		msgSwitch.AddAccessProviderService(opt.TextIdent, provider)
	}
	return
}

func (cfg *configuration) makeInstance() (ctx context.Context, cancel context.CancelFunc, msgSwitch *qabalwrap.MessageSwitch, err error) {
	msgSwitchStateStore, err := qabalwrap.NewStateStore(cfg.StateFolder, qabalwrap.ServiceTypeTextMessageSwitch, cfg.MessageSwitch.TextIdent)
	if nil != err {
		log.Printf("ERROR: cannot setup state store for message switch [%s]: %v", cfg.MessageSwitch.TextIdent, err)
		return
	}
	ctx, cancel = context.WithCancel(context.Background())
	if msgSwitch, err = qabalwrap.NewMessageSwitch(
		msgSwitchStateStore,
		cfg.MessageSwitch.TextIdent,
		cfg.MessageSwitch.DN.Country, cfg.MessageSwitch.DN.Organization,
		cfg.MessageSwitch.PrimaryEnablement); nil != err {
		log.Printf("ERROR: cannot setup message switch [%s]: %v", cfg.MessageSwitch.TextIdent, err)
		return
	}
	httpSrvs := make(map[string]*qabalwrap.HTTPServerService)
	for _, opt := range cfg.HTTPServers {
		srv := qabalwrap.NewHTTPServerService(opt.ListenAddr)
		httpSrvs[opt.TextIdent] = srv
	}
	if err = cfg.setupAccessProviderHTTPServerService(ctx, msgSwitch, httpSrvs); nil != err {
		log.Printf("ERROR: setup HTTP server based access provider failed: %v", err)
		return
	}
	if err = cfg.setupAccessProviderHTTPClientService(ctx, msgSwitch); nil != err {
		log.Printf("ERROR: setup HTTP client based access provider failed: %v", err)
		return
	}
	if err = cfg.setupContentHTTPFetchService(ctx, msgSwitch); nil != err {
		log.Printf("ERROR: setup HTTP content fetcher service failed: %v", err)
		return
	}
	if err = cfg.setupContentHTTPEdgeService(ctx, msgSwitch, httpSrvs); nil != err {
		log.Printf("ERROR: setup content edge HTTP service handler failed: %v", err)
		return
	}
	for ident, srv := range httpSrvs {
		if _, err = msgSwitch.AddHTTPServerService(ident, srv); nil != err {
			log.Printf("ERROR: cannot attach HTTP server service to switch (ident=%s): %v", ident, err)
			return
		}
	}
	return
}

func (cfg *configuration) normalizeMessageSwitch(textIdentSet map[string]struct{}) (err error) {
	if cfg.MessageSwitch.TextIdent == "" {
		err = errors.New("option `ident` of `message-switch` is required")
		return
	}
	if cfg.MessageSwitch.DN.Country == "" {
		err = errors.New("option `c` (Country) in `dn` of `message-switch` is required")
		return
	}
	if cfg.MessageSwitch.DN.Organization == "" {
		err = errors.New("option `o` (Organization) in `dn` of `message-switch` is required")
		return
	}
	cfg.MessageSwitch.TextIdent = strings.ToLower(cfg.MessageSwitch.TextIdent)
	if aux := identnormalize.AlphabetNumberDashOnlyIdentifier(cfg.MessageSwitch.TextIdent, qabalwrap.MaxServiceIdentLength); aux != cfg.MessageSwitch.TextIdent {
		err = fmt.Errorf("invalid `ident` of `message-switch`: %s => %s", cfg.MessageSwitch.TextIdent, aux)
		return
	}
	textIdentSet[cfg.MessageSwitch.TextIdent] = struct{}{}
	return
}

func (cfg *configuration) normalizeHTTPServers(textIdentSet map[string]struct{}) (err error) {
	for idx, opts := range cfg.HTTPServers {
		if opts.TextIdent == "" {
			err = fmt.Errorf("option `ident` of %d-th `http-servers` is required", idx+1)
			return
		}
		opts.TextIdent = strings.ToLower(opts.TextIdent)
		if aux := identnormalize.AlphabetNumberDashOnlyIdentifier(opts.TextIdent, qabalwrap.MaxServiceIdentLength); aux != opts.TextIdent {
			err = fmt.Errorf("invalid `ident` of %d-th `http-servers`: %s => %s", idx+1, opts.TextIdent, aux)
			return
		}
		if _, ok := textIdentSet[opts.TextIdent]; ok {
			err = fmt.Errorf("given `ident` of %d-th `http-servers` existed: %s", idx+1, opts.TextIdent)
			return
		}
		textIdentSet[opts.TextIdent] = struct{}{}
	}
	return
}

func (cfg *configuration) normalizeAccessProviderHTTPServers(textIdentSet map[string]struct{}) (err error) {
	for idx, opts := range cfg.AccessProviders.HTTPServers {
		if opts.TextIdent == "" {
			err = fmt.Errorf("option `ident` of %d-th `access-providers/http-servers` is required", idx+1)
			return
		}
		opts.TextIdent = strings.ToLower(opts.TextIdent)
		if aux := identnormalize.AlphabetNumberDashOnlyIdentifier(opts.TextIdent, qabalwrap.MaxServiceIdentLength); aux != opts.TextIdent {
			err = fmt.Errorf("invalid `ident` of %d-th `access-providers/http-servers`: %s => %s", idx+1, opts.TextIdent, aux)
			return
		}
		if _, ok := textIdentSet[opts.TextIdent]; ok {
			err = fmt.Errorf("given `ident` of %d-th `access-providers/http-servers` existed: %s", idx+1, opts.TextIdent)
			return
		}
		if opts.LinkServerIdent == "" {
			err = fmt.Errorf("option `attach-to` is required but %d-th (%s) `access-providers/http-servers` got empty value", idx+1, opts.TextIdent)
			return
		}
		if opts.HTTPHost == "" {
			err = fmt.Errorf("option `http-host` is required but %d-th (%s) `access-providers/http-servers` got empty value", idx+1, opts.TextIdent)
			return
		}
		opts.HTTPHost = strings.ToLower(opts.HTTPHost)
		if len(opts.AccessChannels) < 1 {
			err = fmt.Errorf("option `channels` is required but %d-th (%s) `access-providers/http-servers` got empty value", idx+1, opts.TextIdent)
			return
		}
		for _, chOpts := range opts.AccessChannels {
			if chOpts.MessageBufferSize == 0 {
				chOpts.MessageBufferSize = 1
			}
		}
		textIdentSet[opts.TextIdent] = struct{}{}
	}
	return
}

func (cfg *configuration) normalizeAccessProviderHTTPClients(textIdentSet map[string]struct{}) (err error) {
	for idx, opts := range cfg.AccessProviders.HTTPClients {
		if opts.TextIdent == "" {
			err = fmt.Errorf("option `ident` of %d-th `access-providers/http-clients` is required", idx+1)
			return
		}
		opts.TextIdent = strings.ToLower(opts.TextIdent)
		if aux := identnormalize.AlphabetNumberDashOnlyIdentifier(opts.TextIdent, qabalwrap.MaxServiceIdentLength); aux != opts.TextIdent {
			err = fmt.Errorf("invalid `ident` of %d-th `access-providers/http-clients`: %s => %s", idx+1, opts.TextIdent, aux)
			return
		}
		if _, ok := textIdentSet[opts.TextIdent]; ok {
			err = fmt.Errorf("given `ident` of %d-th `access-providers/http-clients` existed: %s", idx+1, opts.TextIdent)
			return
		}
		if opts.TargetServerURL == "" {
			err = fmt.Errorf("option `target-url` is required but %d-th (%s) `access-providers/http-clients` got empty value", idx+1, opts.TextIdent)
			return
		}
		if opts.ExchangeMode == qabalwrap.HTTPClientAccessUnknownMode {
			err = fmt.Errorf("option `exchange-mode` is required but %d-th (%s) `access-providers/http-clients` got empty or invalid value", idx+1, opts.TextIdent)
			return
		}
		if opts.MessageBufferSize == 0 {
			opts.MessageBufferSize = 1
		}
		textIdentSet[opts.TextIdent] = struct{}{}
	}
	return
}

func (cfg *configuration) normalizeContentFetcherHTTPService(textIdentSet map[string]struct{}) (err error) {
	for idx, opts := range cfg.ContentFetchers {
		if opts.TextIdent == "" {
			err = fmt.Errorf("option `ident` of %d-th `content-fetchers` is required", idx+1)
			return
		}
		opts.TextIdent = strings.ToLower(opts.TextIdent)
		if aux := identnormalize.AlphabetNumberDashOnlyIdentifier(opts.TextIdent, qabalwrap.MaxServiceIdentLength); aux != opts.TextIdent {
			err = fmt.Errorf("invalid `ident` of %d-th `content-fetchers`: %s => %s", idx+1, opts.TextIdent, aux)
			return
		}
		if _, ok := textIdentSet[opts.TextIdent]; ok {
			err = fmt.Errorf("given `ident` of %d-th `content-fetchers` existed: %s", idx+1, opts.TextIdent)
			return
		}
		if opts.MaxFetchSessionCount < 1 {
			opts.MaxFetchSessionCount = 128
		}
		textIdentSet[opts.TextIdent] = struct{}{}
	}
	return
}

func (cfg *configuration) normalizeContentEdgeHTTPService(textIdentSet map[string]struct{}) (err error) {
	for idx, opts := range cfg.ContentEdges {
		if opts.TextIdent == "" {
			err = fmt.Errorf("option `ident` of %d-th `content-edges` is required", idx+1)
			return
		}
		opts.TextIdent = strings.ToLower(opts.TextIdent)
		if aux := identnormalize.AlphabetNumberDashOnlyIdentifier(opts.TextIdent, qabalwrap.MaxServiceIdentLength); aux != opts.TextIdent {
			err = fmt.Errorf("invalid `ident` of %d-th `content-edges`: %s => %s", idx+1, opts.TextIdent, aux)
			return
		}
		if _, ok := textIdentSet[opts.TextIdent]; ok {
			err = fmt.Errorf("given `ident` of %d-th `content-edges` existed: %s", idx+1, opts.TextIdent)
			return
		}
		if opts.LinkServerIdent == "" {
			err = fmt.Errorf("option `attach-to` is required but %d-th (%s) `content-edges` got empty value", idx+1, opts.TextIdent)
			return
		}
		if opts.HTTPHost == "" {
			err = fmt.Errorf("option `http-host` is required but %d-th (%s) `content-edges` got empty value", idx+1, opts.TextIdent)
			return
		}
		opts.HTTPHost = strings.ToLower(opts.HTTPHost)
		if opts.FetcherIdent == "" {
			err = fmt.Errorf("option `fetch-from` is required but %d-th (%s) `content-edges` got empty value", idx+1, opts.TextIdent)
			return
		}
		opts.FetcherIdent = strings.ToLower(opts.FetcherIdent)
		if aux := identnormalize.AlphabetNumberDashOnlyIdentifier(opts.FetcherIdent, qabalwrap.MaxServiceIdentLength); aux != opts.FetcherIdent {
			err = fmt.Errorf("invalid `fetch-from` of %d-th `content-edges`: %s => %s", idx+1, opts.FetcherIdent, aux)
			return
		}
		if opts.MaxTransferSessionCount < 1 {
			opts.MaxTransferSessionCount = 128
		}
		textIdentSet[opts.TextIdent] = struct{}{}
	}
	return
}

func (cfg *configuration) normalize() (err error) {
	if cfg.StateFolder == "" {
		err = errors.New("option `state-folder` is required")
		return
	}
	if cfg.StateFolder, err = filepath.Abs(cfg.StateFolder); nil != err {
		err = fmt.Errorf("cannot have absolute path of config file [%s]: %w", cfg.StateFolder, err)
		return
	}
	textIdentSet := make(map[string]struct{})
	if err = cfg.normalizeMessageSwitch(textIdentSet); nil != err {
		return
	}
	if err = cfg.normalizeHTTPServers(textIdentSet); nil != err {
		return
	}
	if err = cfg.normalizeAccessProviderHTTPServers(textIdentSet); nil != err {
		return
	}
	if err = cfg.normalizeAccessProviderHTTPClients(textIdentSet); nil != err {
		return
	}
	if err = cfg.normalizeContentEdgeHTTPService(textIdentSet); nil != err {
		return
	}
	if err = cfg.normalizeContentFetcherHTTPService(textIdentSet); nil != err {
		return
	}
	return
}

func loadConfiguration(cfgFilePath string) (cfg *configuration, err error) {
	if cfgFilePath, err = filepath.Abs(cfgFilePath); nil != err {
		log.Printf("ERROR: cannot expand given config file path [%s]: %v", cfgFilePath, err)
		return
	}
	fp, err := os.Open(cfgFilePath)
	if nil != err {
		log.Printf("ERROR: cannot open config file [%s]: %v", cfgFilePath, err)
		return
	}
	defer fp.Close()
	decoder := yaml.NewDecoder(fp)
	var cfgInst configuration
	if err = decoder.Decode(&cfgInst); nil != err {
		return
	}
	if err = cfgInst.normalize(); nil != err {
		return
	}
	cfg = &cfgInst
	return
}
