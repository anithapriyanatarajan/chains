/*
Copyright 2020 The Tekton Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package kms creates a signer using a key management server
package kms

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/tektoncd/chains/pkg/config"
	"knative.dev/pkg/logging"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tektoncd/chains/pkg/chains/signing"
)

// Signer exposes methods to sign payloads using a KMS
type Signer struct {
	signature.SignerVerifier
}

// NewSigner returns a configured Signer
func NewSigner(ctx context.Context, cfg config.KMSSigner) (*Signer, error) {
	kmsOpts := []signature.RPCOption{}

	// Checks if the vault address provide by the user is a valid address or not
	if cfg.Auth.Address != "" {
		vaultAddress, err := url.Parse(cfg.Auth.Address)
		if err != nil {
			return nil, err
		}

		var vaultUrl *url.URL
		switch {
		case vaultAddress.Port() != "":
			vaultUrl = vaultAddress
		case vaultAddress.Scheme == "http":
			vaultUrl = &url.URL{
				Scheme: vaultAddress.Scheme,
				Host:   vaultAddress.Host + ":80",
			}
		case vaultAddress.Scheme == "https":
			vaultUrl = &url.URL{
				Scheme: vaultAddress.Scheme,
				Host:   vaultAddress.Host + ":443",
			}
		case vaultAddress.Scheme == "":
			vaultUrl = &url.URL{
				Scheme: "http",
				Host:   cfg.Auth.Address + ":80",
			}
		case vaultAddress.Scheme != "" && vaultAddress.Scheme != "http" && vaultAddress.Scheme != "https":
			vaultUrl = &url.URL{
				Scheme: "http",
				Host:   cfg.Auth.Address,
			}
			if vaultUrl.Port() == "" {
				vaultUrl.Host = cfg.Auth.Address + ":80"
			}
		}

		if vaultUrl != nil {
			conn, err := net.DialTimeout("tcp", vaultUrl.Host, 5*time.Second)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
		} else {
			return nil, fmt.Errorf("Error connecting to URL %s\n", cfg.Auth.Address)
		}
	}

	// pass through configuration options to RPCAuth used by KMS in sigstore
	rpcAuth := options.RPCAuth{
		Address: cfg.Auth.Address,
		//Token:   cfg.Auth.Token,
		OIDC: options.RPCAuthOIDC{
			Role: cfg.Auth.OIDC.Role,
			Path: cfg.Auth.OIDC.Path,
		},
	}

	// get token from file VAULT_TOKEN, a mounted secret at signers.kms.auth.token-dir or
	// as direct value set from signers.kms.auth.token.
	// If both values are set, priority will be given to token-dir.

	if cfg.Auth.TokenDir != "" {
		rpcAuthToken, err := getRPCAuthToken(cfg.Auth.TokenDir)
		if err != nil {
			return nil, err
		}
		rpcAuth.Token = rpcAuthToken
		_, err = watchSigner(ctx, cfg)
		if err != nil {
			return nil, err
		}
	} else {
		rpcAuth.Token = cfg.Auth.Token
	}

	// get token from spire
	if cfg.Auth.Spire.Sock != "" {
		token, err := newSpireToken(ctx, cfg)
		if err != nil {
			return nil, err
		}
		rpcAuth.OIDC.Token = token
	}
	kmsOpts = append(kmsOpts, options.WithRPCAuthOpts(rpcAuth))
	// get the signer/verifier from sigstore
	k, err := kms.Get(ctx, cfg.KMSRef, crypto.SHA256, kmsOpts...)
	if err != nil {
		return nil, err
	}
	return &Signer{
		SignerVerifier: k,
	}, nil
}

// ErrNothingToWatch is an error that's returned when the signers do not have anything to "watch"
var ErrNothingToWatch = fmt.Errorf("signer has nothing to watch")

// WatchSigner returns a channel that receives a new signer each time it needs to be updated
func watchSigner(ctx context.Context, cfg config.KMSSigner) (chan *Signer, error) {
	logger := logging.FromContext(ctx)

	// Set up watcher only when `signers.kms.auth.token-dir` is set
	if cfg.Auth.TokenDir == "" {
		return nil, ErrNothingToWatch
	}

	logger.Infof("setting up fsnotify watcher for directory: %s", cfg.Auth.TokenDir)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	defer watcher.Close()

	pathsToWatch := []string{
		// token-dir/VAULT_TOKEN is where the VAULT_TOKEN environment
		// variable is expected to be mounted, either manually or via a Kubernetes secret, etc.
		filepath.Join(cfg.Auth.TokenDir, "VAULT_TOKEN"),
		filepath.Join(cfg.Auth.TokenDir, "..data"),
	}

	singerChan := make(chan *Signer)
	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				logger.Infof("received event: %s, path: %s", event.Op.String(), event.Name)
				// Only respond to create/write/remove events in the directory
				if !(event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Remove)) {
					continue
				}

				if !slices.Contains(pathsToWatch, event.Name) {
					continue
				}

				updatedEnv, err := getRPCAuthToken(cfg.Auth.TokenDir)
				if err != nil {
					logger.Error(err)
					singerChan <- nil
				}
				if updatedEnv != os.Getenv("VAULT_TOKEN") {
					logger.Infof("directory %s has been updated, reconfiguring rpcAuthToken...", cfg.Auth.TokenDir)

					// Now that TOKEN has been updated, we should update the signer again
					newSigner, err := NewSigner(ctx, cfg)
					if err != nil {
						logger.Error(err)
						singerChan <- nil
					} else {
						// Storing the backend in the signer so everyone has access to the up-to-date backend
						singerChan <- newSigner
					}
				} else {
					logger.Infof("VAULT_TOKEN has not changed in path: %s, signer auth will not be reconfigured", cfg.Auth.TokenDir)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error(err)
			}
		}
	}()

	// Add a path.
	err = watcher.Add(cfg.Auth.TokenDir)
	if err != nil {
		return nil, err
	}
	return singerChan, nil
}

// getVaultToken retreives token from the given mount path
func getRPCAuthToken(dir string) (string, error) {
	vaultEnv := "VAULT_TOKEN"
	stat, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// If directory does not exist, then create it. This is needed for
			// the fsnotify watcher.
			// fsnotify does not receive events if the path that it's watching
			// is created later.
			if err := os.MkdirAll(dir, 0755); err != nil {
				return "", err
			}
			return "", nil
		}
		return "", err
	}
	// If the path exists but is not a directory, then throw an error
	if !stat.IsDir() {
		return "", fmt.Errorf("path specified %s is not a directory", dir)
	}

	filePath := filepath.Join(dir, vaultEnv)
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	// A trailing newline is fairly common in mounted files, let's remove it.
	fileDataNormalized := strings.TrimSuffix(string(fileData), "\n")
	return fileDataNormalized, nil
}

// newSpireToken retrieves an SVID token from Spire
func newSpireToken(ctx context.Context, cfg config.KMSSigner) (string, error) {
	jwtSource, err := workloadapi.NewJWTSource(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.Auth.Spire.Sock)),
	)
	if err != nil {
		return "", err
	}
	svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: cfg.Auth.Spire.Audience})
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

// Type returns the type of the signer
func (s *Signer) Type() string {
	return signing.TypeKMS
}

// Cert there is no cert, return nothing
func (s *Signer) Cert() string {
	return ""
}

// Chain there is no chain, return nothing
func (s *Signer) Chain() string {
	return ""
}
