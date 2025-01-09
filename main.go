package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/spf13/cobra"
)

var (
	disableColor bool
	RunningPort  int
)

var command = &cobra.Command{
	Use:   "git-proxy",
	Short: "Run service",
	Run:   run,
}

func init() {
	command.PersistentFlags().BoolVarP(&disableColor, "disable-color", "", false, "disable color output")
	command.PersistentFlags().IntVarP(&RunningPort, "running-port", "p", 30000, "disable color output")
}

func main() {
	if err := command.Execute(); err != nil {
		log.Fatal(err)
	}
}

const CtxKeyRequestURL = "request url"

var acceptedDomain = []string{
	"github.com",
	"raw.github.com",
	"raw.githubusercontent.com",
	"gist.github.com",
}

type HTTPError struct {
	Message string `json:"message"`
}

func (e *HTTPError) Error() string {
	return e.Message
}

func newError(msg string) *HTTPError {
	return &HTTPError{Message: msg}
}

func run(*cobra.Command, []string) {
	listen := M.ParseSocksaddr(":" + strconv.Itoa(RunningPort))
	listener := listenTCP(listen)
	chiRouter := chi.NewRouter()
	chiRouter.Group(func(r chi.Router) {
		r.Use(middleware.RealIP)
		r.Use(setContext)
		r.Use(commonLog)
		r.Get("/", hello)
		r.Mount("/", finalHandler())
	})
	server := &http.Server{
		Addr:    listener.Addr().String(),
		Handler: chiRouter,
	}
	go func() {
		err := server.Serve(listener)
		if err != nil {
			log.Fatal(err)
		}
	}()
	log.Info("start http serve success")
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)
	defer signal.Stop(osSignals)
	<-osSignals
}

func listenTCP(address M.Socksaddr) net.Listener {
	var listener net.Listener
	for {
		var err error
		listener, err = net.Listen("tcp", address.String())
		if err == nil {
			break
		}
		address.Port = address.Port + 1
	}
	log.Info("listening tcp port ", address.Port)
	return listener
}
func hello(w http.ResponseWriter, r *http.Request) {
	render.Status(r, http.StatusOK)
	render.PlainText(w, r, "hello to visit git-proxy")
}

func setContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(log.ContextWithNewID(r.Context())))
	})
}

func commonLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aim := r.URL.Path
		if r.URL.RawQuery != "" {
			aim += "?" + r.URL.RawQuery
		}
		if r.URL.Fragment != "" {
			aim += "#" + r.URL.Fragment
		} else if r.URL.RawFragment != "" {
			aim += r.URL.RawFragment
		}
		log.InfoContext(r.Context(), "new ", r.Method, " request from ", r.RemoteAddr, " to ", aim)
		next.ServeHTTP(w, r)
	})
}

func finalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, domain := range acceptedDomain {
			if strings.HasPrefix(r.URL.Path, "/"+domain+"/") {
				requestURL, _ := url.Parse("https:/" + r.URL.Path)
				requestURL.User = r.URL.User
				requestURL.RawQuery = r.URL.RawQuery
				requestURL.Fragment = r.URL.Fragment
				requestURL.RawFragment = r.URL.RawFragment
				ctx := context.WithValue(r.Context(), CtxKeyRequestURL, requestURL)
				sendRequest.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			if r.Referer() == "" {
				continue
			}
			refererURL, err := url.Parse(r.Referer())
			if err != nil {
				continue
			}
			if strings.HasPrefix(refererURL.Path, "/"+domain+"/") {
				http.Redirect(w, r, "/"+domain+"/"+r.URL.Path, http.StatusTemporaryRedirect)
				return
			}
		}
		unsupportedHost.ServeHTTP(w, r)
	})
}

var unsupportedHost = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	err := E.New("unsupported host")
	log.ErrorContext(r.Context(), err)
	render.Status(r, http.StatusInternalServerError)
	render.JSON(w, r, newError(err.Error()))
})

var sendRequest = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestURL := ctx.Value(CtxKeyRequestURL).(*url.URL)
	request, err := http.NewRequest(r.Method, requestURL.String(), r.Body)
	if err != nil {
		err = E.Cause(err, "build request")
		log.ErrorContext(ctx, err)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	for key, values := range r.Header {
		if key == "Host" {
			continue
		}
		delete(request.Header, key)
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	request.URL.User = r.URL.User
	request.URL.RawQuery = r.URL.RawQuery
	request.URL.Fragment = r.URL.Fragment
	request.URL.RawFragment = r.URL.RawFragment
	request.Header = r.Header
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		err = E.Cause(err, "send request")
		log.ErrorContext(ctx, err)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		delete(w.Header(), key)
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
	log.InfoContext(ctx, "success proxy request: ", requestURL, " , method: ", request.Method, " , status: ", response.StatusCode)
})
