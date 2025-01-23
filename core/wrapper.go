package core

import (
	"bytes"
	"compress/gzip"
	"log"
	"net/http"
	"strings"
)

type Wrapper struct {
	Handler *Handler
}

func (wrapper *Wrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Header.Get("User-Agent"), r.Header.Get("Accept-Encoding"))
	// r.Body = io.NopCloser(io.TeeReader(r.Body, os.Stderr))
	wrapper.Handler.ServeHTTP(&gzipWrapper{w, r, 200}, r)
}

type gzipWrapper struct {
	w          http.ResponseWriter
	r          *http.Request
	statusCode int
}

func (g *gzipWrapper) Header() http.Header {
	return g.w.Header()
}

func (g *gzipWrapper) Write(b []byte) (int, error) {
	if b == nil {
		g.w.WriteHeader(g.statusCode)
		return 0, nil
	}

	s := g.r.Header.Get("Accept-Encoding")
	for _, val := range strings.Split(s, ", ") {
		if val == "gzip" {
			g.Header().Add("Content-Encoding", "gzip")
			buf := bytes.NewBuffer(nil)
			gzipw := gzip.NewWriter(buf)

			if k, e := gzipw.Write(b); e != nil {
				return k, e
			} else if e := gzipw.Close(); e != nil {
				return k, e
			} else {
				g.w.WriteHeader(g.statusCode)
				return g.w.Write(buf.Bytes())
			}
		}
	}
	g.w.WriteHeader(g.statusCode)
	return g.w.Write(b)
}

func (g *gzipWrapper) WriteHeader(statusCode int) {
	g.statusCode = statusCode
}
