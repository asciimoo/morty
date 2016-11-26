package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/html"
	"golang.org/x/text/encoding/charmap"
)

const (
	STATE_DEFAULT     int = 0
	STATE_IN_STYLE    int = 1
	STATE_IN_NOSCRIPT int = 2
)

var CLIENT *fasthttp.Client = &fasthttp.Client{
	MaxResponseBodySize: 10 * 1024 * 1024, // 10M
}

var CSS_URL_REGEXP *regexp.Regexp = regexp.MustCompile("url\\((['\"]?)[ \\t\\f]*([\u0009\u0021\u0023-\u0026\u0028\u002a-\u007E]+)(['\"]?)\\)?")

var UNSAFE_ELEMENTS [][]byte = [][]byte{
	[]byte("applet"),
	[]byte("canvas"),
	[]byte("embed"),
	//[]byte("iframe"),
	[]byte("script"),
}

var SAFE_ATTRIBUTES [][]byte = [][]byte{
	[]byte("abbr"),
	[]byte("accesskey"),
	[]byte("align"),
	[]byte("alt"),
	[]byte("as"),
	[]byte("autocomplete"),
	[]byte("charset"),
	[]byte("checked"),
	[]byte("class"),
	[]byte("content"),
	[]byte("contenteditable"),
	[]byte("contextmenu"),
	[]byte("dir"),
	[]byte("for"),
	[]byte("height"),
	[]byte("hidden"),
	[]byte("id"),
	[]byte("lang"),
	[]byte("media"),
	[]byte("method"),
	[]byte("name"),
	[]byte("nowrap"),
	[]byte("placeholder"),
	[]byte("property"),
	[]byte("rel"),
	[]byte("spellcheck"),
	[]byte("tabindex"),
	[]byte("target"),
	[]byte("title"),
	[]byte("translate"),
	[]byte("type"),
	[]byte("value"),
	[]byte("width"),
}

var SELF_CLOSING_ELEMENTS [][]byte = [][]byte{
	[]byte("area"),
	[]byte("base"),
	[]byte("br"),
	[]byte("col"),
	[]byte("embed"),
	[]byte("hr"),
	[]byte("img"),
	[]byte("input"),
	[]byte("keygen"),
	[]byte("link"),
	[]byte("meta"),
	[]byte("param"),
	[]byte("source"),
	[]byte("track"),
	[]byte("wbr"),
}

type Proxy struct {
	Key            []byte
	RequestTimeout time.Duration
}

type RequestConfig struct {
	Key     []byte
	BaseURL *url.URL
}

var HTML_FORM_EXTENSION string = `<input type="hidden" name="mortyurl" value="%s" /><input type="hidden" name="mortyhash" value="%s" />`

var HTML_BODY_EXTENSION string = `
<div id="mortyheader">
  <input type="checkbox" id="mortytoggle" autocomplete="off" />
  <div><p>This is a proxified and sanitized view of the page,<br />visit <a href="%s" rel="noreferrer">original site</a>.</p><p><label for="mortytoggle">hide</label></p></div>
</div>
<style>
#mortyheader { position: fixed; padding: 12px 12px 12px 0; margin: 0; box-sizing: content-box; top: 15%%; left: 0; max-width: 140px; color: #444; overflow: hidden; z-index: 110000; font-size: 12px; line-height: normal; }
#mortyheader a { color: #3498db; font-weight: bold; }
#mortyheader p { padding: 0 0 0.7em 0; margin: 0; }
#mortyheader > div { padding: 8px; font-size: 12px !important; font-family: sans !important; border-width: 4px 4px 4px 0; border-style: solid; border-color: #1abc9c; background: #FFF; line-height: 1em; }
#mortyheader label { text-align: right; cursor: pointer; display: block; color: #444; padding: 0; margin: 0; }
input[type=checkbox]#mortytoggle { display: none; }
input[type=checkbox]#mortytoggle:checked ~ div { display: none; }
</style>
`

func (p *Proxy) RequestHandler(ctx *fasthttp.RequestCtx) {

	if appRequestHandler(ctx) {
		return
	}

	requestHash := popRequestParam(ctx, []byte("mortyhash"))

	requestURI := popRequestParam(ctx, []byte("mortyurl"))

	if requestURI == nil {
		p.serveMainPage(ctx, 200, nil)
		return
	}

	if p.Key != nil {
		if !verifyRequestURI(requestURI, requestHash, p.Key) {
			// HTTP status code 403 : Forbidden
			p.serveMainPage(ctx, 403, errors.New(`invalid "mortyhash" parameter`))
			return
		}
	}

	parsedURI, err := url.Parse(string(requestURI))

	if strings.HasSuffix(parsedURI.Host, ".onion") {
		// HTTP status code 501 : Not Implemented
		p.serveMainPage(ctx, 501, errors.New("Tor urls are not supported yet"))
		return
	}

	if err != nil {
		// HTTP status code 500 : Internal Server Error
		p.serveMainPage(ctx, 500, err)
		return
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetConnectionClose()

	reqQuery := parsedURI.Query()
	ctx.QueryArgs().VisitAll(func(key, value []byte) {
		reqQuery.Add(string(key), string(value))
	})

	parsedURI.RawQuery = reqQuery.Encode()

	uriStr := parsedURI.String()

	log.Println("getting", uriStr)

	req.SetRequestURI(uriStr)
	req.Header.SetUserAgentBytes([]byte("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"))

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethodBytes(ctx.Method())
	if ctx.IsPost() || ctx.IsPut() {
		req.SetBody(ctx.PostBody())
	}

	err = CLIENT.DoTimeout(req, resp, p.RequestTimeout)

	if err != nil {
		if err == fasthttp.ErrTimeout {
			// HTTP status code 504 : Gateway Time-Out
			p.serveMainPage(ctx, 504, err)
		} else {
			// HTTP status code 500 : Internal Server Error
			p.serveMainPage(ctx, 500, err)
		}
		return
	}

	if resp.StatusCode() != 200 {
		switch resp.StatusCode() {
		case 301, 302, 303, 307, 308:
			loc := resp.Header.Peek("Location")
			if loc != nil {
				rc := &RequestConfig{Key: p.Key, BaseURL: parsedURI}
				url, err := rc.ProxifyURI(string(loc))
				if err == nil {
					ctx.SetStatusCode(resp.StatusCode())
					ctx.Response.Header.Add("Location", url)
					log.Println("redirect to", string(loc))
					return
				}
			}
		}
		error_message := fmt.Sprintf("invalid response: %d", resp.StatusCode())
		p.serveMainPage(ctx, resp.StatusCode(), errors.New(error_message))
		return
	}

	contentType := resp.Header.Peek("Content-Type")

	if contentType == nil {
		// HTTP status code 503 : Service Unavailable
		p.serveMainPage(ctx, 503, errors.New("invalid content type"))
		return
	}

	if bytes.Contains(bytes.ToLower(contentType), []byte("javascript")) {
		// HTTP status code 403 : Forbidden
		p.serveMainPage(ctx, 403, errors.New("forbidden content type"))
		return
	}

	contentInfo := bytes.SplitN(contentType, []byte(";"), 2)

	var responseBody []byte

	if len(contentInfo) == 2 && bytes.Contains(contentInfo[1], []byte("ISO-8859-2")) && bytes.Contains(contentInfo[0], []byte("text")) {
		var err error
		responseBody, err = charmap.ISO8859_2.NewDecoder().Bytes(resp.Body())
		if err != nil {
			// HTTP status code 503 : Service Unavailable
			p.serveMainPage(ctx, 503, err)
			return
		}
	} else {
		responseBody = resp.Body()
	}

	ctx.SetContentType(fmt.Sprintf("%s; charset=UTF-8", contentInfo[0]))

	switch {
	case bytes.Contains(contentType, []byte("css")):
		sanitizeCSS(&RequestConfig{Key: p.Key, BaseURL: parsedURI}, ctx, responseBody)
	case bytes.Contains(contentType, []byte("html")):
		sanitizeHTML(&RequestConfig{Key: p.Key, BaseURL: parsedURI}, ctx, responseBody)
	default:
		if ctx.Request.Header.Peek("Content-Disposition") != nil {
			ctx.Response.Header.AddBytesV("Content-Disposition", ctx.Request.Header.Peek("Content-Disposition"))
		}
		ctx.Write(responseBody)
	}
}

func appRequestHandler(ctx *fasthttp.RequestCtx) bool {
	// serve robots.txt
	if bytes.Equal(ctx.Path(), []byte("/robots.txt")) {
		ctx.SetContentType("text/plain")
		ctx.Write([]byte("User-Agent: *\nDisallow: /\n"))
		return true
	}

	return false
}

func popRequestParam(ctx *fasthttp.RequestCtx, paramName []byte) []byte {
	param := ctx.QueryArgs().PeekBytes(paramName)

	if param == nil {
		param = ctx.PostArgs().PeekBytes(paramName)
		if param != nil {
			ctx.PostArgs().DelBytes(paramName)
		}
	} else {
		ctx.QueryArgs().DelBytes(paramName)
	}

	return param
}

func sanitizeCSS(rc *RequestConfig, out io.Writer, css []byte) {
	// TODO

	urlSlices := CSS_URL_REGEXP.FindAllSubmatchIndex(css, -1)

	if urlSlices == nil {
		out.Write(css)
		return
	}

	startIndex := 0

	for _, s := range urlSlices {
		urlStart := s[4]
		urlEnd := s[5]

		if uri, err := rc.ProxifyURI(string(css[urlStart:urlEnd])); err == nil {
			out.Write(css[startIndex:urlStart])
			out.Write([]byte(uri))
			startIndex = urlEnd
		} else {
			log.Println("cannot proxify css uri:", string(css[urlStart:urlEnd]))
		}
	}
	if startIndex < len(css) {
		out.Write(css[startIndex:len(css)])
	}
}

func sanitizeHTML(rc *RequestConfig, out io.Writer, htmlDoc []byte) {
	r := bytes.NewReader(htmlDoc)
	decoder := html.NewTokenizer(r)
	decoder.AllowCDATA(true)

	unsafeElements := make([][]byte, 0, 8)
	state := STATE_DEFAULT

	for {
		token := decoder.Next()
		if token == html.ErrorToken {
			err := decoder.Err()
			if err != io.EOF {
				log.Println("failed to parse HTML:")
			}
			break
		}

		if len(unsafeElements) == 0 {

			switch token {
			case html.StartTagToken, html.SelfClosingTagToken:
				tag, hasAttrs := decoder.TagName()
				safe := !inArray(tag, UNSAFE_ELEMENTS)
				if !safe {
					if !inArray(tag, SELF_CLOSING_ELEMENTS) {
						var unsafeTag []byte = make([]byte, len(tag))
						copy(unsafeTag, tag)
						unsafeElements = append(unsafeElements, unsafeTag)
					}
					break
				}
				if bytes.Equal(tag, []byte("base")) {
					for {
						attrName, attrValue, moreAttr := decoder.TagAttr()
						if bytes.Equal(attrName, []byte("href")) {
							parsedURI, err := url.Parse(string(attrValue))
							if err == nil {
								rc.BaseURL = parsedURI
							}
						}
						if !moreAttr {
							break
						}
					}
					break
				}
				if bytes.Equal(tag, []byte("noscript")) {
					state = STATE_IN_NOSCRIPT
					break
				}
				var attrs [][][]byte
				if hasAttrs {
					for {
						attrName, attrValue, moreAttr := decoder.TagAttr()
						attrs = append(attrs, [][]byte{
							attrName,
							attrValue,
							[]byte(html.EscapeString(string(attrValue))),
						})
						if !moreAttr {
							break
						}
					}
				}
				if bytes.Equal(tag, []byte("link")) {
					sanitizeLinkTag(rc, out, attrs)
					break
				}

				fmt.Fprintf(out, "<%s", tag)

				if hasAttrs {
					if bytes.Equal(tag, []byte("meta")) {
						sanitizeMetaAttrs(rc, out, attrs)
					} else {
						sanitizeAttrs(rc, out, attrs)
					}
				}

				if token == html.SelfClosingTagToken {
					fmt.Fprintf(out, " />")
				} else {
					fmt.Fprintf(out, ">")
					if bytes.Equal(tag, []byte("style")) {
						state = STATE_IN_STYLE
					}
				}

				if bytes.Equal(tag, []byte("form")) {
					var formURL *url.URL
					for _, attr := range attrs {
						if bytes.Equal(attr[0], []byte("action")) {
							formURL, _ = url.Parse(string(attr[1]))
							formURL = mergeURIs(rc.BaseURL, formURL)
							break
						}
					}
					if formURL == nil {
						formURL = rc.BaseURL
					}
					urlStr := formURL.String()
					var key string
					if rc.Key != nil {
						key = hash(urlStr, rc.Key)
					}
					fmt.Fprintf(out, HTML_FORM_EXTENSION, urlStr, key)

				}

			case html.EndTagToken:
				tag, _ := decoder.TagName()
				writeEndTag := true
				switch string(tag) {
				case "body":
					fmt.Fprintf(out, HTML_BODY_EXTENSION, rc.BaseURL.String())
				case "style":
					state = STATE_DEFAULT
				case "noscript":
					state = STATE_DEFAULT
					writeEndTag = false
				}
				// skip noscript tags - only the tag, not the content, because javascript is sanitized
				if writeEndTag {
					fmt.Fprintf(out, "</%s>", tag)
				}

			case html.TextToken:
				switch state {
				case STATE_DEFAULT:
					fmt.Fprintf(out, "%s", decoder.Raw())
				case STATE_IN_STYLE:
					sanitizeCSS(rc, out, decoder.Raw())
				case STATE_IN_NOSCRIPT:
					sanitizeHTML(rc, out, decoder.Raw())
				}

			case html.DoctypeToken, html.CommentToken:
				out.Write(decoder.Raw())
			}
		} else {
			switch token {
			case html.StartTagToken:
				tag, _ := decoder.TagName()
				if inArray(tag, UNSAFE_ELEMENTS) {
					unsafeElements = append(unsafeElements, tag)
				}

			case html.EndTagToken:
				tag, _ := decoder.TagName()
				if bytes.Equal(unsafeElements[len(unsafeElements)-1], tag) {
					unsafeElements = unsafeElements[:len(unsafeElements)-1]
				}
			}
		}
	}
}

func sanitizeLinkTag(rc *RequestConfig, out io.Writer, attrs [][][]byte) {
	exclude := false
	for _, attr := range attrs {
		attrName := attr[0]
		attrValue := attr[1]
		if bytes.Equal(attrName, []byte("rel")) {
			if bytes.Equal(attrValue, []byte("dns-prefetch")) {
				exclude = true
				break
			}
		}
		if bytes.Equal(attrName, []byte("as")) {
			if bytes.Equal(attrValue, []byte("script")) {
				exclude = true
				break
			}
		}
	}

	if !exclude {
		out.Write([]byte("<link"))
		for _, attr := range attrs {
			sanitizeAttr(rc, out, attr[0], attr[1], attr[2])
		}
		out.Write([]byte(">"))
	}
}

func sanitizeMetaAttrs(rc *RequestConfig, out io.Writer, attrs [][][]byte) {
	var http_equiv []byte
	var content []byte

	for _, attr := range attrs {
		attrName := attr[0]
		attrValue := attr[1]
		if bytes.Equal(attrName, []byte("http-equiv")) {
			http_equiv = bytes.ToLower(attrValue)
		}
		if bytes.Equal(attrName, []byte("content")) {
			content = attrValue
		}
	}

	urlIndex := bytes.Index(bytes.ToLower(content), []byte("url="))
	if bytes.Equal(http_equiv, []byte("refresh")) && urlIndex != -1 {
		contentUrl := content[urlIndex+4:]
		// special case of <meta http-equiv="refresh" content="0; url='example.com/url.with.quote.outside'">
		if len(contentUrl) >= 2 && (contentUrl[0] == byte('\'') || contentUrl[0] == byte('"')) {
			if contentUrl[0] == contentUrl[len(contentUrl)-1] {
				contentUrl = contentUrl[1 : len(contentUrl)-1]
			}
		}
		// output proxify result
		if uri, err := rc.ProxifyURI(string(contentUrl)); err == nil {
			fmt.Fprintf(out, ` http-equiv="refresh" content="%surl=%s"`, content[:urlIndex], uri)
		}
	} else {
		sanitizeAttrs(rc, out, attrs)
	}

}

func sanitizeAttrs(rc *RequestConfig, out io.Writer, attrs [][][]byte) {
	for _, attr := range attrs {
		sanitizeAttr(rc, out, attr[0], attr[1], attr[2])
	}
}

func sanitizeAttr(rc *RequestConfig, out io.Writer, attrName, attrValue, escapedAttrValue []byte) {
	if inArray(attrName, SAFE_ATTRIBUTES) {
		fmt.Fprintf(out, " %s=\"%s\"", attrName, escapedAttrValue)
		return
	}
	switch string(attrName) {
	case "src", "href", "action":
		if uri, err := rc.ProxifyURI(string(attrValue)); err == nil {
			fmt.Fprintf(out, " %s=\"%s\"", attrName, uri)
		} else {
			log.Println("cannot proxify uri:", string(attrValue))
		}
	case "style":
		cssAttr := bytes.NewBuffer(nil)
		sanitizeCSS(rc, cssAttr, attrValue)
		fmt.Fprintf(out, " %s=\"%s\"", attrName, html.EscapeString(string(cssAttr.Bytes())))
	}
}

func mergeURIs(u1, u2 *url.URL) *url.URL {
	return u1.ResolveReference(u2)
}

func (rc *RequestConfig) ProxifyURI(uri string) (string, error) {
	// remove javascript protocol
	if strings.HasPrefix(uri, "javascript:") {
		return "", nil
	}
	// TODO check malicious data: - e.g. data:script
	if strings.HasPrefix(uri, "data:") {
		return uri, nil
	}

	if len(uri) > 0 && uri[0] == '#' {
		return uri, nil
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	u = mergeURIs(rc.BaseURL, u)

	uri = u.String()

	if rc.Key == nil {
		return fmt.Sprintf("./?mortyurl=%s", url.QueryEscape(uri)), nil
	}
	return fmt.Sprintf("./?mortyhash=%s&mortyurl=%s", hash(uri, rc.Key), url.QueryEscape(uri)), nil
}

func inArray(b []byte, a [][]byte) bool {
	for _, b2 := range a {
		if bytes.Equal(b, b2) {
			return true
		}
	}
	return false
}

func hash(msg string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyRequestURI(uri, hashMsg, key []byte) bool {
	h := make([]byte, hex.DecodedLen(len(hashMsg)))
	_, err := hex.Decode(h, hashMsg)
	if err != nil {
		log.Println("hmac error:", err)
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(uri)
	return hmac.Equal(h, mac.Sum(nil))
}

func (p *Proxy) serveMainPage(ctx *fasthttp.RequestCtx, statusCode int, err error) {
	ctx.SetContentType("text/html")
	ctx.SetStatusCode(statusCode)
	ctx.Write([]byte(`<!doctype html>
<head>
<title>MortyProxy</title>
<meta name="viewport" content="width=device-width, initial-scale=1 , maximum-scale=1.0, user-scalable=1" />
<style>
html { height: 100%; }
body { min-height : 100%; display: flex; flex-direction:column; font-family: 'Garamond', 'Georgia', serif; text-align: center; color: #444; background: #FAFAFA; margin: 0; padding: 0; font-size: 1.1em; }
input { border: 1px solid #888; padding: 0.3em; color: #444; background: #FFF; font-size: 1.1em; }
input[placeholder] { width:80%; }
a { text-decoration: none; #2980b9; }
h1, h2 { font-weight: 200; margin-bottom: 2rem; }
h1 { font-size: 3em; }
.container { flex:1; min-height: 100%; margin-bottom: 1em; }
.footer { margin: 1em; }
.footer p { font-size: 0.8em; }
</style>
</head>
<body>
	<div class="container">
		<h1>MortyProxy</h1>
`))
	if err != nil {
		log.Println("error:", err)
		ctx.Write([]byte("<h2>Error: "))
		ctx.Write([]byte(html.EscapeString(err.Error())))
		ctx.Write([]byte("</h2>"))
	}
	if p.Key == nil {
		ctx.Write([]byte(`
		<form action="post">
		Visit url: <input placeholder="https://url.." name="mortyurl" autofocus />
		<input type="submit" value="go" />
		</form>`))
	} else {
		ctx.Write([]byte(`<h3>Warning! This instance does not support direct URL opening.</h3>`))
	}
	ctx.Write([]byte(`
	</div>
	<div class="footer">
		<p>Morty rewrites web pages to exclude malicious HTML tags and CSS/HTML attributes. It also replaces external resource references to prevent third-party information leaks.<br />
		<a href="https://github.com/asciimoo/morty">view on github</a>
		</p>
	</div>
</body>
</html>`))
}

func main() {

	listen := flag.String("listen", "127.0.0.1:3000", "Listen address")
	key := flag.String("key", "", "HMAC url validation key (hexadecimal encoded) - leave blank to disable")
	ipv6 := flag.Bool("ipv6", false, "Allow IPv6 HTTP requests")
	requestTimeout := flag.Uint("timeout", 2, "Request timeout")
	flag.Parse()

	if *ipv6 {
		CLIENT.Dial = fasthttp.DialDualStack
	}

	p := &Proxy{RequestTimeout: time.Duration(*requestTimeout) * time.Second}

	if *key != "" {
		p.Key = []byte(*key)
	}

	log.Println("listening on", *listen)

	if err := fasthttp.ListenAndServe(*listen, p.RequestHandler); err != nil {
		log.Fatal("Error in ListenAndServe:", err)
	}
}
