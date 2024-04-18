package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"

	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/renderer/html"
)

func (d *daemon) getUserFromGinContext(c *gin.Context) (AdminClaims, error) {
	sid, exists := c.Get("sid")
	if !exists {
		return AdminClaims{}, errors.New("sid does not exist in gin context")
	}
	adminClaims, err := d.db.GetAdminUserBySid(c, sid.(string))
	if err != nil {
		return AdminClaims{}, err
	}
	return AdminClaims{
		Username:     adminClaims.Username,
		Sid:          adminClaims.Sid.String(),
		Email:        adminClaims.Email,
		Organization: adminClaims.Organization,
		Role:         adminClaims.Role,
		Jti:          string(c.MustGet("jti").(string)),
		Exp:          int64(c.MustGet("exp").(float64)),
		LabQuota:     adminClaims.LabQuota,
	}, nil
}

func unpackTeamClaims(c *gin.Context) TeamClaims {
	return TeamClaims{
		Username: string(c.MustGet("sub").(string)),
		Email:    string(c.MustGet("email").(string)),
		Jti:      string(c.MustGet("jti").(string)),
		Exp:      int64(c.MustGet("exp").(float64)),
		EventTag: string(c.MustGet("eventTag").(string)),
	}
}

func assemblePolicies(s [][]string, org string) ([][]string, error) {
	regex, err := regexp.Compile("(^.*::$)")
	if err != nil {
		return nil, err
	}
	var policies [][]string
	for _, p := range s {
		var policy []string
		for _, v := range p {
			if regex.MatchString(v) || v == "" {
				policy = append(policy, fmt.Sprintf("%s%s", v, org))
			} else {
				policy = append(policy, v)
			}
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func sanitizeUnsafeMarkdown(md []byte) ([]byte, error) {
	var buf bytes.Buffer
	renderer := goldmark.New(
		goldmark.WithRendererOptions(html.WithUnsafe()),
	)
	if err := renderer.Convert(md, &buf); err != nil {
		return nil, err
	}
	unsafeHtml := buf.Bytes()

	html := bluemonday.UGCPolicy().SanitizeBytes(unsafeHtml)
	return html, nil
}

// Sort categories to be alphabetic order
func sortCategories(categories []*eproto.GetCategoriesResponse_Category) {
	sort.Slice(categories, func(p, q int) bool {
		return categories[p].Name < categories[q].Name
	})
	for i, category := range categories {
		if category.Name == "Starters" {
			categories[0], categories[i] = categories[i], categories[0]
		}
	}
}

// Sort exercises into alphabetical order
func sortExercises(exercises []*eproto.Exercise) {
	sort.Slice(exercises, func(p, q int) bool {
		return exercises[p].Name < exercises[q].Name
	})
}

func protobufToJson(message proto.Message) (string, error) {
	marshaler := jsonpb.Marshaler{
		EnumsAsInts:  false,
		EmitDefaults: false,
		Indent:       "  ",
	}

	return marshaler.MarshalToString(message)
}
