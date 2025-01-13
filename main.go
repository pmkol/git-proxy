package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/sagernet/fswatch"
	L "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/spf13/cobra"
)

var log = L.NewDefaultFactory(
	context.Background(),
	L.Formatter{
		BaseTime:        time.Now(),
		FullTimestamp:   true,
		TimestampFormat: "-0700 2006-01-02 15:04:05",
	},
	os.Stdout,
	"",
	nil,
	false,
).Logger()

var client = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var (
	disableColor   bool
	runningPort    int
	domainListPath string
	blacklistPath  string
)

var Blacklist []RepoInfo

var AcceptDomain = []string{
	"github.com",
	"raw.github.com",
	"raw.githubusercontent.com",
	"gist.github.com",
	"objects.githubusercontent.com",
	"gist.githubusercontent.com",
	"codeload.github.com",
	"api.github.com",
}

var command = &cobra.Command{
	Use:   "git-proxy",
	Short: "A HTTP service to proxy git requests",
	Run:   run,
}

func init() {
	command.PersistentFlags().BoolVarP(&disableColor, "disable-color", "", false, "disable color output")
	command.PersistentFlags().IntVarP(&runningPort, "running-port", "p", 30000, "disable color output")
	command.PersistentFlags().StringVarP(&domainListPath, "domain-list-path", "d", "domainlist.txt", "set accept domain")
	command.PersistentFlags().StringVarP(&blacklistPath, "blacklist-path", "b", "blacklist.txt", "set repository blacklist")
}

func main() {
	if err := command.Execute(); err != nil {
		log.Fatal(err)
	}
}

type HTTPError struct {
	Message string `json:"message"`
	Example string `json:"example"`
}

func (e *HTTPError) Error() string {
	return e.Message
}

func newError(msg string) *HTTPError {
	return &HTTPError{
		Message: msg,
		Example: "https://abc.com/https://github.com/github/docs.git",
	}
}

func run(*cobra.Command, []string) {
	if watcher, err := loadDomainList(); err == nil {
		err = watcher.Start()
		if err == nil {
			log.Info("Watching accept domain list")
			defer watcher.Close()
		} else {
			log.Error(E.Cause(err, "Start watch accept domain list"))
			watcher.Close()
		}
	}
	if watcher, err := loadBlackList(); err == nil {
		err = watcher.Start()
		if err == nil {
			log.Info("Watching repository blacklist")
			defer watcher.Close()
		} else {
			log.Error(E.Cause(err, "Start watch repository blacklist"))
			watcher.Close()
		}
	}
	listen := M.ParseSocksaddr(":" + strconv.Itoa(runningPort))
	listener := listenTCP(listen)
	chiRouter := chi.NewRouter()
	chiRouter.Group(func(r chi.Router) {
		r.Use(middleware.RealIP)
		r.Use(setContext)
		r.Use(commonLog)
		r.Get("/", hello)
		r.Mount("/", finalHandle())
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
	log.Info("Start http serve success")
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)
	defer signal.Stop(osSignals)
	<-osSignals
}

type FileReader struct {
	LineChan    chan string
	CloseSignal chan struct{}
}

func NewFileReader(path string) (*FileReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	reader := FileReader{
		LineChan:    make(chan string),
		CloseSignal: make(chan struct{}),
	}
	go func() {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if len(line) == 0 {
				continue
			}
			lr := []rune(line)
			if lr[0] == '#' || (len(lr) > 1 && lr[0] == '/' && lr[1] == '/') {
				continue
			}
			for i, r := range lr {
				if r == '#' || (r == '/' && i < len(lr)-1 && lr[i+1] == '/') {
					line = strings.TrimSpace(string(lr[:i]))
					break
				}
			}
			reader.LineChan <- line
		}
		reader.CloseSignal <- struct{}{}
	}()
	return &reader, nil
}

func (r *FileReader) Close() {
	close(r.LineChan)
	close(r.CloseSignal)
}

func loadDomainList() (*fswatch.Watcher, error) {
	err := loadDomainListData()
	if err != nil {
		return nil, err
	}
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{domainListPath},
		Callback: func(path string) {
			log.Info("Accept domain list changed, reloading")
			loadDomainListData()
		},
	})
	if err != nil {
		log.Error(E.Cause(err, "Create accept domain list watcher"))
		return nil, err
	}
	return watcher, nil
}

func loadDomainListData() error {
	reader, err := NewFileReader(domainListPath)
	if err != nil {
		return err
	}
	var domainList []string
	var needBreak bool
	for {
		if needBreak {
			break
		}
		select {
		case <-reader.CloseSignal:
			needBreak = true
			continue
		case line := <-reader.LineChan:
			if net.ParseIP(line) != nil {
				continue
			}
			domainList = append(domainList, line)
		}
	}
	if len(domainList) > 0 {
		AcceptDomain = domainList
		log.Info("Custom accept domain list loaded")
	} else {
		log.Warn("Custom accept domain list is empty")
	}
	return nil
}

func loadBlackList() (*fswatch.Watcher, error) {
	err := loadBlackListData()
	if err != nil {
		return nil, err
	}
	path, _ := filepath.Abs(blacklistPath)
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{path},
		Callback: func(path string) {
			log.Info("Repository blacklist changed, reloading")
			loadBlackListData()
		},
	})
	if err != nil {
		log.Error(E.Cause(err, "Create repository blacklist watcher"))
		return nil, err
	}
	return watcher, nil
}

func loadBlackListData() error {
	reader, err := NewFileReader(blacklistPath)
	if err != nil {
		return err
	}
	var blacklist []RepoInfo
	for {
		var needBreak bool
		select {
		case line := <-reader.LineChan:
			if !common.Any([]rune(line), func(it rune) bool {
				return it == '/'
			}) {
				continue
			}
			splited := strings.Split(line, "/")
			user := splited[0]
			repo := splited[1]
			if user == "" {
				user = "*"
			}
			if repo == "" {
				repo = "*"
			} else if strings.HasSuffix(repo, ".git") {
				repo = repo[:len(repo)-4]
			}
			blacklist = append(blacklist, RepoInfo{user, repo})
		case <-reader.CloseSignal:
			needBreak = true
		}
		if needBreak {
			break
		}
	}
	if len(blacklist) > 0 {
		Blacklist = blacklist
		log.Info("Custom repository blacklist loaded")
	} else {
		log.Warn("Custom repository blacklist is empty")
	}
	return nil
}

type RepoInfo struct {
	User string
	Repo string
}

func (r *RepoInfo) Match(user string, repo string) bool {
	return EasyWildcardMatch(strings.ToLower(user), strings.ToLower(r.User)) && EasyWildcardMatch(strings.ToLower(repo), strings.ToLower(r.Repo))
}

func EasyWildcardMatch(s string, p string) bool {
	if p == "*" || (s == "" && p == "") {
		return true
	}
	if s == "" || p == "" {
		return false
	}
	pr := []rune(p)
	sr := []rune(s)
	var nextS, nextP string
	if len(pr) > 1 {
		nextP = string(pr[1:])
	}
	if len(sr) > 1 {
		nextS = string(sr[1:])
	}
	if pr[0] == '*' {
		return EasyWildcardMatch(s, nextP) || EasyWildcardMatch(nextS, nextP) || EasyWildcardMatch(nextS, p)
	} else if pr[0] == '?' {
		return EasyWildcardMatch(nextS, nextP)
	} else {
		return sr[0] == pr[0] && EasyWildcardMatch(nextS, nextP)
	}
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
	log.Info("Listening tcp port ", address.Port)
	return listener
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.Status(r, http.StatusOK)
	render.PlainText(w, r, "Hello to visit git-proxy")
}

func setContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(L.ContextWithNewID(r.Context())))
	})
}

func commonLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.InfoContext(r.Context(), "New ", r.Method, " request from ", r.RemoteAddr, " to ", r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func finalHandle() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHandler(r).ServeHTTP(w, r)
	})
}

func finalHandler(r *http.Request) http.Handler {
	requestURIURL, err := url.Parse(r.URL.RequestURI()[1:])
	if err != nil {
		return responseWithError(E.Cause(err, "Parse request uri as url"))
	}
	if common.Any(AcceptDomain, func(it string) bool {
		return it == requestURIURL.Host
	}) {
		if len(requestURIURL.Path) < 2 {
			return sendRequestWithURL(requestURIURL)
		}
		splited := strings.Split(requestURIURL.Path[1:], "/")
		var user, repo string
		if len(splited) == 0 || (len(splited) == 1 && len(splited[0]) == 0) {
			return sendRequestWithURL(requestURIURL)
		}
		user = splited[0]
		if len(splited) > 1 {
			repo = splited[1]
		}
		if repo == "" {
			log.InfoContext(r.Context(), "Found user: ", user)
		} else {
			log.InfoContext(r.Context(), "Found user: ", user, " repository: ", repo)
		}
		if common.Any(Blacklist, func(it RepoInfo) bool {
			result := it.Match(strings.ToLower(user), strings.ToLower(repo))
			if result {
				log.InfoContext(r.Context(), "Match blocked repository: ", it.User, "/", it.Repo)
			}
			return result
		}) {
			return responseWithWarn("Blocked repository")
		} else {
			return sendRequestWithURL(requestURIURL)
		}
	}
	if r.Referer() != "" {
		rawRefererURL, err := url.Parse(r.Referer())
		if err != nil {
			return responseWithError(E.Cause(err, "Parse referer url"))
		}
		refererURL, err := url.Parse(rawRefererURL.RequestURI()[1:])
		if err != nil {
			return responseWithError(E.Cause(err, "Parse referer url request uri as url"))
		}
		if common.Any(AcceptDomain, func(it string) bool {
			return it == refererURL.Host
		}) {
			finalURL, err := refererURL.Parse(r.URL.RequestURI())
			if err != nil {
				return responseWithError(E.Cause(err, "Parse request uri as path with referer url"))
			}
			return responseWithRedirect(finalURL)
		}
	}
	if requestURIURL.Scheme == "" {
		return responseWithError(E.New("URL scheme request"))
	}
	if requestURIURL.Host == "" {
		return responseWithError(E.New("URL host request"))
	}
	return responseWithError(E.New("Unsupported url host"))
}

func responseWithWarn(msg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WarnContext(r.Context(), msg)
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, msg)
	})
}

func responseWithError(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.ErrorContext(r.Context(), err)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
	})
}

func responseWithRedirect(URL *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.InfoContext(r.Context(), "Success redirect request: ", r.URL.RequestURI(), " to: /", URL.String())
		w.Header().Set("Location", "/"+URL.String())
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
}

func sendRequestWithURL(URL *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request, err := http.NewRequest(r.Method, URL.String(), r.Body)
		if err != nil {
			responseWithError(E.Cause(err, "Build request")).ServeHTTP(w, r)
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
		response, err := client.Do(request)
		if err != nil {
			responseWithError(E.Cause(err, "Send request")).ServeHTTP(w, r)
			return
		}
		defer response.Body.Close()
		isRedirectResponse := common.Any([]int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect}, func(it int) bool {
			return it == response.StatusCode
		})
		for key, values := range response.Header {
			delete(w.Header(), key)
			for _, value := range values {
				if isRedirectResponse && key == "Location" && len(value) > 0 && []rune(value)[0] != '/' {
					if locationURL, err := url.Parse(value); err == nil && common.Any(AcceptDomain, func(it string) bool {
						return it == locationURL.Host
					}) {
						value = "/" + value
					}
				}
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
		log.InfoContext(ctx, "Success proxy request: ", URL, " , method: ", request.Method, " , status: ", response.StatusCode)
	})
}
