package baauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"strings"
)

var aks = map[string]AK{}

func Init() {
	userAks := viper.Sub("settings.aks")
	switch userAks.GetString("type") {
	case "file":
		uaks := []UserAks{}
		path, err := filepath.Abs(userAks.GetString("path"))
		if err != nil {
			log.Fatalln(err)
		}
		bs, err := ioutil.ReadFile(path)
		if err != nil {
			log.Println(err)
		}
		yaml.Unmarshal(bs, &uaks)
		for _, v := range uaks {
			for _, ak := range v.Aks {
				if _, ok := aks[ak.KeyId]; !ok {
					ak.Username = v.Username
					aks[ak.KeyId] = ak
				} else {
					log.Fatalln(ak.KeyId, "is exists!")
				}
			}
		}
	}
}

func BaAuth(c *gin.Context) (string, error) {
	dateTime := c.GetHeader("Date")
	authorization := getParams(`((?P<tag>\w+)(\s+))?(?P<keyId>\w+):(?P<signature>([A-Za-z0-9+/]+(=+)?))`, c.GetHeader("Authorization"))

	if ak, ok := aks[authorization["keyId"]]; ok {
		signature := Signature(c.Request.Method, c.Request.URL.EscapedPath(), dateTime, ak.KeySecret)
		if signstr, ok := authorization["signature"]; ok {
			if signstr == signature {
				return ak.Username, nil
			}
		}
	}
	return "", errors.New("Baauth failed!")
}

type UserAks struct {
	Username string `json:"username" yaml:"username"`
	Aks      []AK   `json:"aks" yaml:"aks"`
}

type AK struct {
	KeyId     string `json:"id" yaml:"id"`
	KeySecret string `json:"secret" yaml:"secret"`
	Desc      string `json:"desc" yaml:"desc"`
	Username  string `json:"-" yaml:"-"`
}

func Signature(method, uri, dateTime, secret string) string {
	str2Sign := fmt.Sprintf("%s %s\n%s", method, uri, dateTime)
	hash := hmac.New(sha1.New, []byte(secret))
	io.WriteString(hash, str2Sign)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func getParams(reg, val string) (paramsMap map[string]string) {
	var compRegEx = regexp.MustCompile(reg)
	match := compRegEx.FindStringSubmatch(val)

	paramsMap = make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			if strings.TrimSpace(name) == "" {
				continue
			}
			paramsMap[name] = match[i]
		}
	}
	return
}
