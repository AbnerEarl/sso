/**
 * @author: yangchangjia
 * @email 1320259466@qq.com
 * @date: 2024/4/28 14:44
 * @desc: about the role of class.
 */

package main

import (
	"github.com/AbnerEarl/goutils/redisc"
	"github.com/AbnerEarl/sso"
	"golang.org/x/oauth2"
)

func main() {
	var cfg = sso.OidcConfig{
		OidcProvider: "http://0.0.0.0:5556/provider",
		Config: &oauth2.Config{
			ClientID:     "bbb-client",
			ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV2",
			RedirectURL:  "http://www.bbb.com:8090/callback",
			Scopes:       []string{"openid", "offline_access", "profile", "email", "groups"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://127.0.0.1:5556/provider/auth",
				TokenURL: "http://127.0.0.1:5556/provider/token",
			},
		},
		AppTopDomain: []string{".aaa.com", ".bbb.com"},
		//RedisClusterCli:  redisc.InitRedisCluster([]string{"127.0.0.1:6379"}, 100, 10, "", ""),
		RedisCli: redisc.InitRedis("127.0.0.1:6379", 0, 100, 10, "", ""),
	}
	sso.StartServer(8090, cfg)
}
