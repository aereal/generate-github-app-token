package generatetoken

import (
	"context"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v45/github"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"
)

func NewGenerator(outStream, errStream io.Writer) *Generator {
	return &Generator{outStream: outStream, errStream: errStream}
}

type Generator struct {
	outStream io.Writer
	errStream io.Writer

	privateKeyPath      string
	appID               int64
	tokenLiveness       time.Duration
	installedRepository string
}

func (g *Generator) Run(argv []string) int {
	var exitCode int
	if err := g.run(argv); err != nil {
		fmt.Fprintln(g.errStream, err)
		if a, ok := err.(interface{ ExitCode() int }); ok {
			exitCode = a.ExitCode()
		}
	}
	return exitCode
}

func (g *Generator) shouldGenerateInstallationToken() bool {
	return g.installedRepository != ""
}

func (g *Generator) run(argv []string) error {
	fset := flag.NewFlagSet(argv[0], flag.ContinueOnError)
	fset.Int64Var(&g.appID, "id", 0, "GitHub App ID")
	fset.StringVar(&g.privateKeyPath, "private-key", "", "GitHub App private key")
	fset.DurationVar(&g.tokenLiveness, "liveness", time.Minute, "token liveness")
	fset.StringVar(&g.installedRepository, "repo", "", "installed repository qualified name; indicates the generator to generate repository installation token")
	if err := fset.Parse(argv[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if g.privateKeyPath == "" {
		return errors.New("-private-key is required")
	}
	if g.appID == 0 {
		return errors.New("-id is required")
	}
	appToken, err := g.generateAppToken()
	if err != nil {
		return fmt.Errorf("generateAuthToken(): %w", err)
	}
	if g.shouldGenerateInstallationToken() {
		installationToken, err := g.generateInstallationToken(context.Background(), string(appToken))
		if err != nil {
			return fmt.Errorf("generateInstallationToken(): %w", err)
		}
		fmt.Fprintln(g.outStream, installationToken)
	} else {
		fmt.Fprintln(g.outStream, string(appToken))
	}
	return nil
}

func (g *Generator) generateInstallationToken(ctx context.Context, appToken string) (string, error) {
	client := github.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: appToken})))
	owner, repo, found := strings.Cut(g.installedRepository, "/")
	if !found {
		return "", fmt.Errorf("malformed repository name: %s", g.installedRepository)
	}
	installation, _, err := client.Apps.FindRepositoryInstallation(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("Apps.FindRepositoryInstallation(): %w", err)
	}
	out, _, err := client.Apps.CreateInstallationToken(ctx, installation.GetID(), &github.InstallationTokenOptions{})
	if err != nil {
		return "", fmt.Errorf("Apps.CreateInstallationToken(): %w", err)
	}
	return out.GetToken(), nil
}

func (g *Generator) generateAppToken() ([]byte, error) {
	rawKey, err := ioutil.ReadFile(g.privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadFile(%s): %w", g.privateKeyPath, err)
	}
	combinedKey, err := jwk.ParseKey(rawKey, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("jwk.ParseKey(): %w", err)
	}
	var key rsa.PrivateKey
	if err := combinedKey.Raw(&key); err != nil {
		return nil, fmt.Errorf("jwk.Key.Raw(): %w", err)
	}
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(strconv.FormatInt(g.appID, 10)).
		IssuedAt(now).
		Expiration(now.Add(g.tokenLiveness)).
		Build()
	if err != nil {
		return nil, fmt.Errorf("jwt.Builder.Build(): %w", err)
	}
	return jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
}
