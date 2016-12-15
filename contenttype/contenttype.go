package contenttype

import (
	"mime"
	"strings"
)

type ContentType struct {
	TopLevelType string
	SubType      string
	Suffix       string
	Parameters   map[string]string
}

func (contenttype *ContentType) String() string {
	var mimetype string
	if contenttype.Suffix == "" {
		if contenttype.SubType == "" {
			mimetype = contenttype.TopLevelType
		} else {
			mimetype = contenttype.TopLevelType + "/" + contenttype.SubType
		}
	} else {
		mimetype = contenttype.TopLevelType + "/" + contenttype.SubType + "+" + contenttype.Suffix
	}
	return mime.FormatMediaType(mimetype, contenttype.Parameters)
}

func (contenttype *ContentType) Equals(other ContentType) bool {
	if contenttype.TopLevelType != other.TopLevelType ||
		contenttype.SubType != other.SubType ||
		contenttype.Suffix != other.Suffix ||
		len(contenttype.Parameters) != len(other.Parameters) {
		return false
	}
	for k, v := range contenttype.Parameters {
		if other.Parameters[k] != v {
			return false
		}
	}
	return true
}

func (contenttype *ContentType) FilterParameters(parameters map[string]bool) {
	for k, _ := range contenttype.Parameters {
		if !parameters[k] {
			delete(contenttype.Parameters, k)
		}
	}
}

func ParseContentType(contenttype string) (ContentType, error) {
	mimetype, params, err := mime.ParseMediaType(contenttype)
	if err != nil {
		return ContentType{"", "", "", params}, err
	}
	splitted_mimetype := strings.SplitN(strings.ToLower(mimetype), "/", 2)
	if len(splitted_mimetype) <= 1 {
		return ContentType{splitted_mimetype[0], "", "", params}, nil
	} else {
		splitted_subtype := strings.SplitN(splitted_mimetype[1], "+", 2)
		if len(splitted_subtype) == 1 {
			return ContentType{splitted_mimetype[0], splitted_subtype[0], "", params}, nil
		} else {
			return ContentType{splitted_mimetype[0], splitted_subtype[0], splitted_subtype[1], params}, nil
		}
	}

}

type Filter func(contenttype ContentType) bool

func NewFilterContains(partialMimeType string) Filter {
	return func(contenttype ContentType) bool {
		return strings.Contains(contenttype.TopLevelType, partialMimeType) ||
			strings.Contains(contenttype.SubType, partialMimeType) ||
			strings.Contains(contenttype.Suffix, partialMimeType)
	}
}

func NewFilterEquals(TopLevelType, SubType, Suffix string) Filter {
	return func(contenttype ContentType) bool {
		return ((TopLevelType != "*" && TopLevelType == contenttype.TopLevelType) || (TopLevelType == "*")) &&
			((SubType != "*" && SubType == contenttype.SubType) || (SubType == "*")) &&
			((Suffix != "*" && Suffix == contenttype.Suffix) || (Suffix == "*"))
	}
}

func NewFilterOr(contentTypeFilterList []Filter) Filter {
	return func(contenttype ContentType) bool {
		for _, contentTypeFilter := range contentTypeFilterList {
			if contentTypeFilter(contenttype) {
				return true
			}
		}
		return false
	}
}
