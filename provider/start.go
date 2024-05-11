package provider

import (
	"fmt"
	"github.com/AbnerEarl/sso/provider/start"
	"github.com/spf13/cobra"
	"os"
)

func CommandRoot() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "provider",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(2)
		},
	}
	rootCmd.AddCommand(start.CommandServe())
	rootCmd.AddCommand(start.CommandVersion())
	return rootCmd
}

func StartProvider(configPath string) {
	c := CommandRoot()
	c.SetArgs([]string{"serve", configPath})
	if err := c.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}
