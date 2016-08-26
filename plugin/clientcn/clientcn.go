package clientcn

import (
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/vulcand/vulcand/plugin"
	"net/http"
	"strings"
)

const Type = "clientcn"

type ClientCNMiddleware struct {
	Names []string
}

type ClientCNHandler struct {
	cfg  ClientCNMiddleware
	next http.Handler
}

func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,
		FromOther: FromOther,
		FromCli:   FromCli,
		CliFlags:  CliFlags(),
	}
}

func (c *ClientCNHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, cert := range r.TLS.PeerCertificates {
		for _, name := range cert.DNSNames {
			for _, allowed := range c.cfg.Names {
				if allowed == name {
					c.next.ServeHTTP(w, r)
					return
				}
			}
		}
	}

	w.WriteHeader(http.StatusForbidden)
}

func (c *ClientCNMiddleware) NewHandler(next http.Handler) (http.Handler, error) {
	return &ClientCNHandler{next: next, cfg: *c}, nil
}

func (c *ClientCNMiddleware) String() string {
	return fmt.Sprintf("Names=%v", c.Names)
}

func FromOther(c ClientCNMiddleware) (plugin.Middleware, error) {
	return &ClientCNMiddleware{
		Names: c.Names,
	}, nil
}

func FromCli(c *cli.Context) (plugin.Middleware, error) {
	names := strings.Split(c.String("names"), ",")
	var trimmed []string
	for _, n := range names {
		trimmed = append(trimmed, strings.TrimSpace(n))
	}
	return &ClientCNMiddleware{
		Names: trimmed,
	}, nil
}

// CliFlags will be used by Vulcand construct help and CLI command for the vctl command
func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{Name: "names", Usage: "list of client common names to allow through this middleware"},
	}
}
