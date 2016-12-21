package contenttype

import (
	"testing"
)

type ParseContentTypeTestCase struct {
	Input          string
	ExpectedOutput *ContentType /* or nil if an error is expected */
	ExpectedString *string      /* or nil if equals to Input */
}

var parseContentTypeTestCases []ParseContentTypeTestCase = []ParseContentTypeTestCase{
	ParseContentTypeTestCase{
		"text/html",
		&ContentType{"text", "html", "", map[string]string{}},
		nil,
	},
	ParseContentTypeTestCase{
		"text/svg+xml; charset=UTF-8",
		&ContentType{"text", "svg", "xml", map[string]string{"charset": "UTF-8"}},
		nil,
	},
	ParseContentTypeTestCase{
		"text/",
		nil,
		nil,
	},
	ParseContentTypeTestCase{
		"text; charset=UTF-8",
		&ContentType{"text", "", "", map[string]string{"charset": "UTF-8"}},
		nil,
	},
	ParseContentTypeTestCase{
		"text/+xml; charset=UTF-8",
		&ContentType{"text", "", "xml", map[string]string{"charset": "UTF-8"}},
		nil,
	},
}

type ContentTypeEqualsTestCase struct {
	A, B   ContentType
	Equals bool
}

var Map_Empty map[string]string = map[string]string{}
var Map_A map[string]string = map[string]string{"a": "value_a"}
var Map_B map[string]string = map[string]string{"b": "value_b"}
var Map_AB map[string]string = map[string]string{"a": "value_a", "b": "value_b"}

var ContentType_E ContentType = ContentType{"a", "b", "c", Map_Empty}
var ContentType_A ContentType = ContentType{"a", "b", "c", Map_A}
var ContentType_B ContentType = ContentType{"a", "b", "c", Map_B}
var ContentType_AB ContentType = ContentType{"a", "b", "c", Map_AB}

var contentTypeEqualsTestCases []ContentTypeEqualsTestCase = []ContentTypeEqualsTestCase{
	// TopLevelType, SubType, Suffix
	ContentTypeEqualsTestCase{ContentType_E, ContentType{"a", "b", "c", Map_Empty}, true},
	ContentTypeEqualsTestCase{ContentType_E, ContentType{"o", "b", "c", Map_Empty}, false},
	ContentTypeEqualsTestCase{ContentType_E, ContentType{"a", "o", "c", Map_Empty}, false},
	ContentTypeEqualsTestCase{ContentType_E, ContentType{"a", "b", "o", Map_Empty}, false},
	// Parameters
	ContentTypeEqualsTestCase{ContentType_A, ContentType_A, true},
	ContentTypeEqualsTestCase{ContentType_B, ContentType_B, true},
	ContentTypeEqualsTestCase{ContentType_AB, ContentType_AB, true},
	ContentTypeEqualsTestCase{ContentType_A, ContentType_E, false},
	ContentTypeEqualsTestCase{ContentType_A, ContentType_B, false},
	ContentTypeEqualsTestCase{ContentType_B, ContentType_A, false},
	ContentTypeEqualsTestCase{ContentType_AB, ContentType_A, false},
	ContentTypeEqualsTestCase{ContentType_AB, ContentType_E, false},
	ContentTypeEqualsTestCase{ContentType_A, ContentType_AB, false},
}

type FilterTestCase struct {
	Input       Filter
	TrueValues  []ContentType
	FalseValues []ContentType
}

var filterTestCases []FilterTestCase = []FilterTestCase{
	FilterTestCase{
		NewFilterContains("xml"),
		[]ContentType{
			ContentType{"xml", "", "", Map_Empty},
			ContentType{"text", "xml", "", Map_Empty},
			ContentType{"text", "html", "xml", Map_Empty},
		},
		[]ContentType{
			ContentType{"text", "svg", "", map[string]string{"script": "javascript"}},
			ContentType{"java", "script", "", Map_Empty},
		},
	},
	FilterTestCase{
		NewFilterEquals("application", "xhtml", "*"),
		[]ContentType{
			ContentType{"application", "xhtml", "xml", Map_Empty},
			ContentType{"application", "xhtml", "", Map_Empty},
			ContentType{"application", "xhtml", "zip", Map_Empty},
			ContentType{"application", "xhtml", "zip", Map_AB},
		},
		[]ContentType{
			ContentType{"application", "javascript", "", Map_Empty},
			ContentType{"text", "xhtml", "", Map_Empty},
		},
	},
	FilterTestCase{
		NewFilterEquals("application", "*", ""),
		[]ContentType{
			ContentType{"application", "xhtml", "", Map_Empty},
			ContentType{"application", "javascript", "", Map_Empty},
		},
		[]ContentType{
			ContentType{"text", "xhtml", "", Map_Empty},
			ContentType{"text", "xhtml", "xml", Map_Empty},
		},
	},
	FilterTestCase{
		NewFilterEquals("*", "javascript", ""),
		[]ContentType{
			ContentType{"application", "javascript", "", Map_Empty},
			ContentType{"text", "javascript", "", Map_Empty},
		},
		[]ContentType{
			ContentType{"text", "html", "", Map_Empty},
			ContentType{"text", "javascript", "zip", Map_Empty},
		},
	},
	FilterTestCase{
		NewFilterOr([]Filter{
			NewFilterEquals("application", "*", ""),
			NewFilterEquals("*", "javascript", ""),
		}),
		[]ContentType{
			ContentType{"application", "javascript", "", Map_Empty},
			ContentType{"text", "javascript", "", Map_Empty},
			ContentType{"application", "xhtml", "", Map_Empty},
		},
		[]ContentType{
			ContentType{"text", "html", "", Map_Empty},
			ContentType{"application", "xhtml", "xml", Map_Empty},
		},
	},
}

type FilterParametersTestCase struct {
	Input  map[string]string
	Filter map[string]bool
	Output map[string]string
}

var filterParametersTestCases []FilterParametersTestCase = []FilterParametersTestCase{
	FilterParametersTestCase{
		map[string]string{},
		map[string]bool{"A": true, "B": true},
		map[string]string{},
	},
	FilterParametersTestCase{
		map[string]string{"A": "value_A", "B": "value_B"},
		map[string]bool{},
		map[string]string{},
	},
	FilterParametersTestCase{
		map[string]string{"A": "value_A", "B": "value_B"},
		map[string]bool{"A": true},
		map[string]string{"A": "value_A"},
	},
	FilterParametersTestCase{
		map[string]string{"A": "value_A", "B": "value_B"},
		map[string]bool{"A": true, "B": true},
		map[string]string{"A": "value_A", "B": "value_B"},
	},
}

func TestContentTypeEquals(t *testing.T) {
	for _, testCase := range contentTypeEqualsTestCases {
		if !testCase.A.Equals(testCase.B) && testCase.Equals {
			t.Errorf(`Must be equals "%s"="%s"`, testCase.A, testCase.B)
		} else if testCase.A.Equals(testCase.B) && !testCase.Equals {
			t.Errorf(`Mustn't be equals "%s"!="%s"`, testCase.A, testCase.B)
		}
	}
}

func TestParseContentType(t *testing.T) {
	for _, testCase := range parseContentTypeTestCases {
		// test ParseContentType
		contentType, err := ParseContentType(testCase.Input)
		if testCase.ExpectedOutput == nil {
			// error expected
			if err == nil {
				// but there is no error
				t.Errorf(`Expecting error for "%s"`, testCase.Input)
			}
		} else {
			// no expected error
			if err != nil {
				t.Errorf(`Unexpecting error for "%s" : %s`, testCase.Input, err)
			} else if !contentType.Equals(*testCase.ExpectedOutput) {
				// the parsed contentType doesn't matched
				t.Errorf(`Unexpecting result for "%s", instead got "%s"`, testCase.ExpectedOutput.String(), contentType.String())
			} else {
				// ParseContentType is fine, checking String()
				contentTypeString := contentType.String()
				expectedString := testCase.Input
				if testCase.ExpectedString != nil {
					expectedString = *testCase.ExpectedString
				}
				if contentTypeString != expectedString {
					t.Errorf(`Error with String() output of "%s", got "%s", ContentType{"%s", "%s", "%s", "%s"}`, expectedString, contentTypeString, contentType.TopLevelType, contentType.SubType, contentType.Suffix, contentType.Parameters)
				}
			}
		}
	}
}

func TestFilters(t *testing.T) {
	for _, testCase := range filterTestCases {
		for _, contentType := range testCase.TrueValues {
			if !testCase.Input(contentType) {
				t.Errorf(`Filter "%s" must accept the value "%s"`, testCase.Input, contentType)
			}
		}
		for _, contentType := range testCase.FalseValues {
			if testCase.Input(contentType) {
				t.Errorf(`Filter "%s" mustn't accept the value "%s"`, testCase.Input, contentType)
			}
		}
	}
}

func TestFilterParameters(t *testing.T) {
	for _, testCase := range filterParametersTestCases {
		// copy Input since the map will be modified
		InputCopy := make(map[string]string)
		for k, v := range testCase.Input {
			InputCopy[k] = v
		}
		// apply filter
		contentType := ContentType{"", "", "", InputCopy}
		contentType.FilterParameters(testCase.Filter)
		// test
		contentTypeOutput := ContentType{"", "", "", testCase.Output}
		if !contentTypeOutput.Equals(contentType) {
			t.Errorf(`FilterParameters error : %s becomes %s with this filter %s`, testCase.Input, contentType.Parameters, testCase.Filter)
		}
	}
}
