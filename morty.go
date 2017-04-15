package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"

	"github.com/asciimoo/morty/contenttype"
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

var ALLOWED_CONTENTTYPE_FILTER contenttype.Filter = contenttype.NewFilterOr([]contenttype.Filter{
	// html
	contenttype.NewFilterEquals("text", "html", ""),
	contenttype.NewFilterEquals("application", "xhtml", "xml"),
	// css
	contenttype.NewFilterEquals("text", "css", ""),
	// images
	contenttype.NewFilterEquals("image", "gif", ""),
	contenttype.NewFilterEquals("image", "png", ""),
	contenttype.NewFilterEquals("image", "jpeg", ""),
	contenttype.NewFilterEquals("image", "pjpeg", ""),
	contenttype.NewFilterEquals("image", "webp", ""),
	contenttype.NewFilterEquals("image", "tiff", ""),
	contenttype.NewFilterEquals("image", "vnd.microsoft.icon", ""),
	contenttype.NewFilterEquals("image", "bmp", ""),
	contenttype.NewFilterEquals("image", "x-ms-bmp", ""),
	// fonts
	contenttype.NewFilterEquals("application", "font-otf", ""),
	contenttype.NewFilterEquals("application", "font-ttf", ""),
	contenttype.NewFilterEquals("application", "font-woff", ""),
	contenttype.NewFilterEquals("application", "vnd.ms-fontobject", ""),
})

var ALLOWED_CONTENTTYPE_ATTACHMENT_FILTER contenttype.Filter = contenttype.NewFilterOr([]contenttype.Filter{
	// texts
	contenttype.NewFilterEquals("text", "csv", ""),
	contenttype.NewFilterEquals("text", "tab-separated-value", ""),
	contenttype.NewFilterEquals("text", "plain", ""),
	// API
	contenttype.NewFilterEquals("application", "json", ""),
	// Documents
	contenttype.NewFilterEquals("application", "x-latex", ""),
	contenttype.NewFilterEquals("application", "pdf", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.text", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.spreadsheet", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.presentation", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.graphics", ""),
	// Compressed archives
	contenttype.NewFilterEquals("application", "zip", ""),
	contenttype.NewFilterEquals("application", "gzip", ""),
	contenttype.NewFilterEquals("application", "x-compressed", ""),
	contenttype.NewFilterEquals("application", "x-gtar", ""),
	contenttype.NewFilterEquals("application", "x-compress", ""),
	// Generic binary
	contenttype.NewFilterEquals("application", "octet-stream", ""),
})

var ALLOWED_CONTENTTYPE_PARAMETERS map[string]bool = map[string]bool{
	"charset": true,
}

var UNSAFE_ELEMENTS [][]byte = [][]byte{
	[]byte("applet"),
	[]byte("canvas"),
	[]byte("embed"),
	//[]byte("iframe"),
	[]byte("math"),
	[]byte("script"),
	[]byte("svg"),
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
	[]byte("hreflang"),
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

var LINK_REL_SAFE_VALUES [][]byte = [][]byte{
	[]byte("alternate"),
	[]byte("archives"),
	[]byte("author"),
	[]byte("copyright"),
	[]byte("first"),
	[]byte("help"),
	[]byte("icon"),
	[]byte("index"),
	[]byte("last"),
	[]byte("license"),
	[]byte("manifest"),
	[]byte("next"),
	[]byte("pingback"),
	[]byte("prev"),
	[]byte("publisher"),
	[]byte("search"),
	[]byte("shortcut icon"),
	[]byte("stylesheet"),
	[]byte("up"),
}

var LINK_HTTP_EQUIV_SAFE_VALUES [][]byte = [][]byte{
	// X-UA-Compatible will be added automaticaly, so it can be skipped
	[]byte("date"),
	[]byte("last-modified"),
	[]byte("refresh"), // URL rewrite
	// []byte("location"), TODO URL rewrite
	[]byte("content-language"),
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
<input type="checkbox" id="mortytoggle" autocomplete="off" />
<div id="mortyheader">
  <p>This is a <a href="https://github.com/asciimoo/morty">proxified and sanitized</a> view of the page,<br />visit <a href="%s" rel="noreferrer">original site</a>.</p><p><label for="mortytoggle">hide</label></p>
</div>
<style>
#mortyheader { position: fixed; margin: 0; box-sizing: border-box; -webkit-box-sizing: border-box; top: 15%%; left: 0; max-width: 140px; overflow: hidden; z-index: 2147483647 !important; font-size: 12px; line-height: normal; border-width: 4px 4px 4px 0; border-style: solid; border-color: #1abc9c; background: #FFF; padding: 12px 12px 8px 8px; color: #444; }
#mortyheader * { box-sizing: content-box; margin: 0; border: none; padding: 0; overflow: hidden; z-index: 2147483647 !important; line-height: 1em; font-size: 12px !important; font-family: sans !important; font-weight: normal; text-align: left; text-decoration: none; }
#mortyheader p { padding: 0 0 0.7em 0; display: block; }
#mortyheader a { color: #3498db; font-weight: bold; display: inline; }
#mortyheader label { text-align: right; cursor: pointer; display: block; color: #444; }
input[type=checkbox]#mortytoggle { display: none; }
input[type=checkbox]#mortytoggle:checked ~ div { display: none; visibility: hidden; }
</style>
`

var HTML_HEAD_CONTENT_TYPE string = `<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="referrer" content="no-referrer">
`

var MORTY_HTML_PAGE_START string = `<!doctype html>
<html>
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
`

var MORTY_HTML_PAGE_END string = `
	</div>
	<div class="footer">
		<p>Morty rewrites web pages to exclude malicious HTML tags and CSS/HTML attributes. It also replaces external resource references to prevent third-party information leaks.<br />
		<a href="https://github.com/asciimoo/morty">view on github</a>
		</p>
	</div>
</body>
</html>`

var FAVICON_BYTES []byte

func init() {
	FaviconBase64 := "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQEAYAAABPYyMiAAAABmJLR0T///////8JWPfcAAAACXBIWXMAAABIAAAASABGyWs+AAAAF0lEQVRIx2NgGAWjYBSMglEwCkbBSAcACBAAAeaR9cIAAAAASUVORK5CYII"

	FAVICON_BYTES, _ = base64.StdEncoding.DecodeString(FaviconBase64)
}

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

	if err != nil {
		// HTTP status code 500 : Internal Server Error
		p.serveMainPage(ctx, 500, err)
		return
	}

	// Serve an intermediate page for protocols other than HTTP(S)
	if (parsedURI.Scheme != "http" && parsedURI.Scheme != "https") || strings.HasSuffix(parsedURI.Host, ".onion") {
		p.serveExitMortyPage(ctx, parsedURI)
		return
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetConnectionClose()

	requestURIStr := string(requestURI)

	log.Println("getting", requestURIStr)

	req.SetRequestURI(requestURIStr)
	req.Header.SetUserAgentBytes([]byte("Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0"))

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
				url, err := rc.ProxifyURI(loc)
				if err == nil {
					ctx.SetStatusCode(resp.StatusCode())
					ctx.Response.Header.Add("Location", url)
					log.Println("redirect to", string(loc))
					return
				}
			}
		}
		error_message := fmt.Sprintf("invalid response: %d (%s)", resp.StatusCode(), requestURIStr)
		p.serveMainPage(ctx, resp.StatusCode(), errors.New(error_message))
		return
	}

	contentTypeBytes := resp.Header.Peek("Content-Type")

	if contentTypeBytes == nil {
		// HTTP status code 503 : Service Unavailable
		p.serveMainPage(ctx, 503, errors.New("invalid content type"))
		return
	}

	contentTypeString := string(contentTypeBytes)

	// decode Content-Type header
	contentType, error := contenttype.ParseContentType(contentTypeString)
	if error != nil {
		// HTTP status code 503 : Service Unavailable
		p.serveMainPage(ctx, 503, errors.New("invalid content type"))
		return
	}

	// content-disposition
	contentDispositionBytes := ctx.Request.Header.Peek("Content-Disposition")

	// check content type
	if !ALLOWED_CONTENTTYPE_FILTER(contentType) {
		// it is not a usual content type
		if ALLOWED_CONTENTTYPE_ATTACHMENT_FILTER(contentType) {
			// force attachment for allowed content type
			contentDispositionBytes = contentDispositionForceAttachment(contentDispositionBytes, parsedURI)
		} else {
			// deny access to forbidden content type
			// HTTP status code 403 : Forbidden
			p.serveMainPage(ctx, 403, errors.New("forbidden content type"))
			return
		}
	}

	// HACK : replace */xhtml by text/html
	if contentType.SubType == "xhtml" {
		contentType.TopLevelType = "text"
		contentType.SubType = "html"
		contentType.Suffix = ""
	}

	// conversion to UTF-8
	var responseBody []byte

	if contentType.TopLevelType == "text" {
		e, ename, _ := charset.DetermineEncoding(resp.Body(), contentTypeString)
		if (e != encoding.Nop) && (!strings.EqualFold("utf-8", ename)) {
			responseBody, err = e.NewDecoder().Bytes(resp.Body())
			if err != nil {
				// HTTP status code 503 : Service Unavailable
				p.serveMainPage(ctx, 503, err)
				return
			}
		} else {
			responseBody = resp.Body()
		}
		// update the charset or specify it
		contentType.Parameters["charset"] = "UTF-8"
	} else {
		responseBody = resp.Body()
	}

	//
	contentType.FilterParameters(ALLOWED_CONTENTTYPE_PARAMETERS)

	// set the content type
	ctx.SetContentType(contentType.String())

	// output according to MIME type
	switch {
	case contentType.SubType == "css" && contentType.Suffix == "":
		sanitizeCSS(&RequestConfig{Key: p.Key, BaseURL: parsedURI}, ctx, responseBody)
	case contentType.SubType == "html" && contentType.Suffix == "":
		sanitizeHTML(&RequestConfig{Key: p.Key, BaseURL: parsedURI}, ctx, responseBody)
	default:
		if contentDispositionBytes != nil {
			ctx.Response.Header.AddBytesV("Content-Disposition", contentDispositionBytes)
		}
		ctx.Write(responseBody)
	}
}

// force content-disposition to attachment
func contentDispositionForceAttachment(contentDispositionBytes []byte, url *url.URL) []byte {
	var contentDispositionParams map[string]string

	if contentDispositionBytes != nil {
		var err error
		_, contentDispositionParams, err = mime.ParseMediaType(string(contentDispositionBytes))
		if err != nil {
			contentDispositionParams = make(map[string]string)
		}
	} else {
		contentDispositionParams = make(map[string]string)
	}

	_, fileNameDefined := contentDispositionParams["filename"]
	if !fileNameDefined {
		// TODO : sanitize filename
		contentDispositionParams["fileName"] = filepath.Base(url.Path)
	}

	return []byte(mime.FormatMediaType("attachment", contentDispositionParams))
}

func appRequestHandler(ctx *fasthttp.RequestCtx) bool {
	// serve robots.txt
	if bytes.Equal(ctx.Path(), []byte("/robots.txt")) {
		ctx.SetContentType("text/plain")
		ctx.Write([]byte("User-Agent: *\nDisallow: /\n"))
		return true
	}

	// server favicon.ico
	if bytes.Equal(ctx.Path(), []byte("/favicon.ico")) {
		ctx.SetContentType("image/png")
		ctx.Write(FAVICON_BYTES)
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

		if uri, err := rc.ProxifyURI(css[urlStart:urlEnd]); err == nil {
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

				if bytes.Equal(tag, []byte("meta")) {
					sanitizeMetaTag(rc, out, attrs)
					break
				}

				fmt.Fprintf(out, "<%s", tag)

				if hasAttrs {
					sanitizeAttrs(rc, out, attrs)
				}

				if token == html.SelfClosingTagToken {
					fmt.Fprintf(out, " />")
				} else {
					fmt.Fprintf(out, ">")
					if bytes.Equal(tag, []byte("style")) {
						state = STATE_IN_STYLE
					}
				}

				if bytes.Equal(tag, []byte("head")) {
					fmt.Fprintf(out, HTML_HEAD_CONTENT_TYPE)
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

			case html.CommentToken:
				// ignore comment. TODO : parse IE conditional comment

			case html.DoctypeToken:
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
			if !inArray(attrValue, LINK_REL_SAFE_VALUES) {
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

func sanitizeMetaTag(rc *RequestConfig, out io.Writer, attrs [][][]byte) {
	var http_equiv []byte
	var content []byte

	for _, attr := range attrs {
		attrName := attr[0]
		attrValue := attr[1]
		if bytes.Equal(attrName, []byte("http-equiv")) {
			http_equiv = bytes.ToLower(attrValue)
			// exclude some <meta http-equiv="..." ..>
			if !inArray(http_equiv, LINK_HTTP_EQUIV_SAFE_VALUES) {
				return
			}
		}
		if bytes.Equal(attrName, []byte("content")) {
			content = attrValue
		}
		if bytes.Equal(attrName, []byte("charset")) {
			// exclude <meta charset="...">
			return
		}
	}

	out.Write([]byte("<meta"))
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
		if uri, err := rc.ProxifyURI(contentUrl); err == nil {
			fmt.Fprintf(out, ` http-equiv="refresh" content="%surl=%s"`, content[:urlIndex], uri)
		}
	} else {
		if len(http_equiv) > 0 {
			fmt.Fprintf(out, ` http-equiv="%s"`, http_equiv)
		}
		sanitizeAttrs(rc, out, attrs)
	}
	out.Write([]byte(">"))
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
		if uri, err := rc.ProxifyURI(attrValue); err == nil {
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
	if u2 == nil {
		return u1
	}
	return u1.ResolveReference(u2)
}

// Sanitized URI : removes all runes bellow 32 (included) as the begining and end of URI, and lower case the scheme.
// avoid memory allocation (except for the scheme)
func sanitizeURI(uri []byte) ([]byte, string) {
	first_rune_index := 0
	first_rune_seen := false
	scheme_last_index := -1
	buffer := bytes.NewBuffer(make([]byte, 0, 10))

	// remove trailing space and special characters
	uri = bytes.TrimRight(uri, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20")

	// loop over byte by byte
	for i, c := range uri {
		// ignore special characters and space (c <= 32)
		if c > 32 {
			// append to the lower case of the rune to buffer
			if c < utf8.RuneSelf && 'A' <= c && c <= 'Z' {
				c = c + 'a' - 'A'
			}

			buffer.WriteByte(c)

			// update the first rune index that is not a special rune
			if !first_rune_seen {
				first_rune_index = i
				first_rune_seen = true
			}

			if c == ':' {
				// colon rune found, we have found the scheme
				scheme_last_index = i
				break
			} else if c == '/' || c == '?' || c == '\\' || c == '#' {
				// special case : most probably a relative URI
				break
			}
		}
	}

	if scheme_last_index != -1 {
		// scheme found
		// copy the "lower case without special runes scheme" before the ":" rune
		scheme_start_index := scheme_last_index - buffer.Len() + 1
		copy(uri[scheme_start_index:], buffer.Bytes())
		// and return the result
		return uri[scheme_start_index:], buffer.String()
	} else {
		// scheme NOT found
		return uri[first_rune_index:], ""
	}
}

func (rc *RequestConfig) ProxifyURI(uri []byte) (string, error) {
	// sanitize URI
	uri, scheme := sanitizeURI(uri)

	// remove javascript protocol
	if scheme == "javascript:" {
		return "", nil
	}

	// TODO check malicious data: - e.g. data:script
	if scheme == "data:" {
		if bytes.HasPrefix(uri, []byte("data:image/png")) ||
			bytes.HasPrefix(uri, []byte("data:image/jpeg")) ||
			bytes.HasPrefix(uri, []byte("data:image/pjpeg")) ||
			bytes.HasPrefix(uri, []byte("data:image/gif")) ||
			bytes.HasPrefix(uri, []byte("data:image/webp")) {
			// should be safe
			return string(uri), nil
		} else {
			// unsafe data
			return "", nil
		}
	}

	// parse the uri
	u, err := url.Parse(string(uri))
	if err != nil {
		return "", err
	}

	// get the fragment (with the prefix "#")
	fragment := ""
	if len(u.Fragment) > 0 {
		fragment = "#" + u.Fragment
	}

	// reset the fragment: it is not included in the mortyurl
	u.Fragment = ""

	// merge the URI with the document URI
	u = mergeURIs(rc.BaseURL, u)

	// simple internal link ?
	// some web pages describe the whole link https://same:auth@same.host/same.path?same.query#new.fragment
	if u.Scheme == rc.BaseURL.Scheme &&
		(rc.BaseURL.User == nil || (u.User != nil && u.User.String() == rc.BaseURL.User.String())) &&
		u.Host == rc.BaseURL.Host &&
		u.Path == rc.BaseURL.Path &&
		u.RawQuery == rc.BaseURL.RawQuery {
		// the fragment is the only difference between the document URI and the uri parameter
		return fragment, nil
	}

	// return full URI and fragment (if not empty)
	morty_uri := u.String()

	if rc.Key == nil {
		return fmt.Sprintf("./?mortyurl=%s%s", url.QueryEscape(morty_uri), fragment), nil
	}
	return fmt.Sprintf("./?mortyhash=%s&mortyurl=%s%s", hash(morty_uri, rc.Key), url.QueryEscape(morty_uri), fragment), nil
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

func (p *Proxy) serveExitMortyPage(ctx *fasthttp.RequestCtx, uri *url.URL) {
	ctx.SetContentType("text/html")
	ctx.SetStatusCode(403)
	ctx.Write([]byte(MORTY_HTML_PAGE_START))
	ctx.Write([]byte("<h2>You are about to exit MortyProxy</h2>"))
	ctx.Write([]byte("<p>Following</p><p><a href=\""))
	ctx.Write([]byte(html.EscapeString(uri.String())))
	ctx.Write([]byte("\" rel=\"noreferrer\">"))
	ctx.Write([]byte(html.EscapeString(uri.String())))
	ctx.Write([]byte("</a></p><p>the content of this URL will be <b>NOT</b> sanitized.</p>"))
	ctx.Write([]byte(MORTY_HTML_PAGE_END))
}

func (p *Proxy) serveMainPage(ctx *fasthttp.RequestCtx, statusCode int, err error) {
	ctx.SetContentType("text/html; charset=UTF-8")
	ctx.SetStatusCode(statusCode)
	ctx.Write([]byte(MORTY_HTML_PAGE_START))
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
	ctx.Write([]byte(MORTY_HTML_PAGE_END))
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
