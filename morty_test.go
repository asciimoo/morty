package main

import (
	"bytes"
	"net/url"
	"testing"
)

type AttrTestCase struct {
	AttrName       []byte
	AttrValue      []byte
	ExpectedOutput []byte
}

type SanitizeURITestCase struct {
	Input          []byte
	ExpectedOutput []byte
	ExpectedScheme string
}

type StringTestCase struct {
	Input          string
	ExpectedOutput string
}

var attrTestData []*AttrTestCase = []*AttrTestCase{
	&AttrTestCase{
		[]byte("href"),
		[]byte("./x"),
		[]byte(` href="./?mortyurl=http%3A%2F%2F127.0.0.1%2Fx"`),
	},
	&AttrTestCase{
		[]byte("src"),
		[]byte("http://x.com/y"),
		[]byte(` src="./?mortyurl=http%3A%2F%2Fx.com%2Fy"`),
	},
	&AttrTestCase{
		[]byte("action"),
		[]byte("/z"),
		[]byte(` action="./?mortyurl=http%3A%2F%2F127.0.0.1%2Fz"`),
	},
	&AttrTestCase{
		[]byte("onclick"),
		[]byte("console.log(document.cookies)"),
		nil,
	},
}

var sanitizeUriTestData []*SanitizeURITestCase = []*SanitizeURITestCase{
	&SanitizeURITestCase{
		[]byte("http://example.com/"),
		[]byte("http://example.com/"),
		"http:",
	},
	&SanitizeURITestCase{
		[]byte("HtTPs://example.com/     \t"),
		[]byte("https://example.com/"),
		"https:",
	},
	&SanitizeURITestCase{
		[]byte("      Ht  TPs://example.com/     \t"),
		[]byte("https://example.com/"),
		"https:",
	},
	&SanitizeURITestCase{
		[]byte("javascript:void(0)"),
		[]byte("javascript:void(0)"),
		"javascript:",
	},
	&SanitizeURITestCase{
		[]byte("      /path/to/a/file/without/protocol     "),
		[]byte("/path/to/a/file/without/protocol"),
		"",
	},
	&SanitizeURITestCase{
		[]byte("      #fragment     "),
		[]byte("#fragment"),
		"",
	},
	&SanitizeURITestCase{
		[]byte("      qwertyuiop     "),
		[]byte("qwertyuiop"),
		"",
	},
	&SanitizeURITestCase{
		[]byte(""),
		[]byte(""),
		"",
	},
	&SanitizeURITestCase{
		[]byte(":"),
		[]byte(":"),
		":",
	},
	&SanitizeURITestCase{
		[]byte("   :"),
		[]byte(":"),
		":",
	},
	&SanitizeURITestCase{
		[]byte("schéma:"),
		[]byte("schéma:"),
		"schéma:",
	},
}

var urlTestData []*StringTestCase = []*StringTestCase{
	&StringTestCase{
		"http://x.com/",
		"./?mortyurl=http%3A%2F%2Fx.com%2F",
	},
	&StringTestCase{
		"http://a@x.com/",
		"./?mortyurl=http%3A%2F%2Fa%40x.com%2F",
	},
	&StringTestCase{
		"#a",
		"#a",
	},
}

func TestAttrSanitizer(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	for _, testCase := range attrTestData {
		out := bytes.NewBuffer(nil)
		sanitizeAttr(rc, out, testCase.AttrName, testCase.AttrValue, testCase.AttrValue)
		res, _ := out.ReadBytes(byte(0))
		if !bytes.Equal(res, testCase.ExpectedOutput) {
			t.Errorf(
				`Attribute parse error. Name: "%s", Value: "%s", Expected: %s, Got: "%s"`,
				testCase.AttrName,
				testCase.AttrValue,
				testCase.ExpectedOutput,
				res,
			)
		}
	}
}

func TestSanitizeURI(t *testing.T) {
	for _, testCase := range sanitizeUriTestData {
		newUrl, scheme := sanitizeURI(testCase.Input)
		if !bytes.Equal(newUrl, testCase.ExpectedOutput) {
			t.Errorf(
				`URL proxifier error. Expected: "%s", Got: "%s"`,
				testCase.ExpectedOutput,
				newUrl,
			)
		}
		if scheme != testCase.ExpectedScheme {
			t.Errorf(
				`URL proxifier error. Expected: "%s", Got: "%s"`,
				testCase.ExpectedScheme,
				scheme,
			)
		}
	}
}

func TestURLProxifier(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	for _, testCase := range urlTestData {
		newUrl, err := rc.ProxifyURI([]byte(testCase.Input))
		if err != nil {
			t.Errorf("Failed to parse URL: %s", testCase.Input)
		}
		if newUrl != testCase.ExpectedOutput {
			t.Errorf(
				`URL proxifier error. Expected: "%s", Got: "%s"`,
				testCase.ExpectedOutput,
				newUrl,
			)
		}
	}
}

var BENCH_SIMPLE_HTML []byte = []byte(`<!doctype html>
<html>
 <head>
  <title>test</title>
 </head>
 <body>
  <h1>Test heading</h1>
 </body>
</html>`)

func BenchmarkSanitizeSimpleHTML(b *testing.B) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := bytes.NewBuffer(nil)
		sanitizeHTML(rc, out, BENCH_SIMPLE_HTML)
	}
}

var BENCH_COMPLEX_HTML []byte = []byte(`<!doctype html>
<html>
 <head>
  <noscript><meta http-equiv="refresh" content="0; URL=./xy"></noscript>
  <title>test 2</title>
  <script> alert('xy'); </script>
  <link rel="stylesheet" href="./core.bundle.css">
  <style>
   html { background: url(./a.jpg); }
  </style
 </head>
 <body>
  <h1>Test heading</h1>
  <img src="b.png" alt="imgtitle" />
  <form action="/z">
  <input type="submit" style="background: url(http://aa.bb/cc)" >
  </form>
 </body>
</html>`)

func BenchmarkSanitizeComplexHTML(b *testing.B) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := bytes.NewBuffer(nil)
		sanitizeHTML(rc, out, BENCH_COMPLEX_HTML)
	}
}
