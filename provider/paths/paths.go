/**
 * @author: yangchangjia
 * @email 1320259466@qq.com
 * @date: 2024/5/11 17:24
 * @desc: about the role of class.
 */

package paths

import (
	"path"
	"runtime"
)

func GetAbPathByCaller() string {
	var abPath string
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		abPath = path.Dir(path.Dir(filename)) + "/"
	}
	return abPath
}
