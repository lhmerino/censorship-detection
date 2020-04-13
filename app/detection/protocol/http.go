package protocol

import (
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
)

type HttpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcp.Stream
}

func (h *HttpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *HttpReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(h)
	for true {
		if h.isClient {
			req, err := http.ReadRequest(b)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				logger.Error("HTTP-request", "HTTP/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}
			logger.Info("HTTP/%s Request: %s %s\n", h.ident, req.Method, req.URL)
			h.parent.Lock()
			h.parent.Urls = append(h.parent.Urls, req.URL.String())
			h.parent.Unlock()
			req.Body.Close()
			break

			/* HTTP Request Body if needed */
			/*body, err := ioutil.ReadAll(req.Body)
			s := len(body)
			if err != nil {
				Error("HTTP-request-body", "Got body err: %s\n", err)
			} else if h.hexdump {
				Info("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}*/

		} else {
			/* Never run */
			res, err := http.ReadResponse(b, nil)
			var req string
			h.parent.Lock()
			if len(h.parent.Urls) == 0 {
				req = fmt.Sprintf("<no-request-seen>")
			} else {
				req, h.parent.Urls = h.parent.Urls[0], h.parent.Urls[1:]
			}
			h.parent.Unlock()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				logger.Error("HTTP-response", "HTTP/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}
			body, err := ioutil.ReadAll(res.Body)
			s := len(body)
			if err != nil {
				logger.Error("HTTP-response-body", "HTTP/%s: failed to get body(parsed len:%d): %s\n", h.ident, s, err)
			}
			if h.hexdump {
				logger.Info("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			res.Body.Close()
			sym := ","
			if res.ContentLength > 0 && res.ContentLength != int64(s) {
				sym = "!="
			}
			contentType, ok := res.Header["Content-Type"]
			if !ok {
				contentType = []string{http.DetectContentType(body)}
			}
			encoding := res.Header["Content-Encoding"]
			logger.Info("HTTP/%s Response: %s URL:%s (%d%s%d%s) -> %s\n", h.ident, res.Status, req, res.ContentLength, sym, s, contentType, encoding)
			/*if (err == nil || *writeincomplete) && *output != "" {
				base := url.QueryEscape(path.Base(req))
				logger.Info("1")
				if err != nil {
					base = "incomplete-" + base
				}
				base = path.Join(*output, base)
				if len(base) > 250 {
					base = base[:250] + "..."
				}
				if base == *output {
					base = path.Join(*output, "noname")
				}
				logger.Info("2")
				target := base
				n := 0
				for true {
					_, err := os.Stat(target)
					//if os.IsNotExist(err) != nil {
					if err != nil {
						break
					}
					target = fmt.Sprintf("%s-%d", base, n)
					n++
				}
				f, err := os.Create(target)
				logger.Info("3")
				if err != nil {
					Error("HTTP-create", "Cannot create %s: %s\n", target, err)
					continue
				}
				logger.Info("4")
				var r io.Reader
				r = bytes.NewBuffer(body)
				if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
					r, err = gzip.NewReader(r)
					if err != nil {
						Error("HTTP-gunzip", "Failed to gzip decode: %s", err)
					}
				}
				if err == nil {
					w, err := io.Copy(f, r)
					if _, ok := r.(*gzip.Reader); ok {
						r.(*gzip.Reader).Close()
					}
					f.Close()
					if err != nil {
						logger.Error("HTTP-save", "%s: failed to save %s (l:%d): %s\n", h.ident, target, w, err)
					} else {
						logger.Error("%s: Saved %s (l:%d)\n", h.ident, target, w)
					}
				}
			}*/
		}
	}
}
