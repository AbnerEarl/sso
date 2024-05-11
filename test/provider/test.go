/**
 * @author: yangchangjia
 * @email 1320259466@qq.com
 * @date: 2024/5/11 17:17
 * @desc: about the role of class.
 */

package main

import (
	"github.com/AbnerEarl/sso/provider"
	"github.com/AbnerEarl/sso/provider/paths"
)

func main() {
	provider.StartProvider(paths.GetAbPathByCaller() + "config.yaml")
}
