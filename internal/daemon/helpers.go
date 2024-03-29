package daemon

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/renderer/html"
)

func unpackAdminClaims(c *gin.Context) AdminClaims {
	return AdminClaims{
		Username:     string(c.MustGet("sub").(string)),
		Email:        string(c.MustGet("email").(string)),
		Organization: string(c.MustGet("organization").(string)),
		Role:         string(c.MustGet("role").(string)),
		Jti:          string(c.MustGet("jti").(string)),
		Exp:          int64(c.MustGet("exp").(float64)),
	}
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
