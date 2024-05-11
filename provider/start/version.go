package start

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var version = "DEV"

func CommandVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf(
				"Provider Version: %s\nGo Version: %s\nGo OS/ARCH: %s %s\n",
				version,
				runtime.Version(),
				runtime.GOOS,
				runtime.GOARCH,
			)
		},
	}
}
