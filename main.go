package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/elysiera/client-editor/edit"
	"github.com/elysiera/client-editor/repack"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	configFile, tibiaExe string
	srcClient, dstClient string
)

var rootCmd = &cobra.Command{
	Use:   "client-editor",
	Short: "Edit or repack Tibia client",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if configFile != "" {
			viper.SetConfigFile(configFile)
		}
		if err := viper.ReadInConfig(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() {
	repackCmd := &cobra.Command{
		Use:   "repack",
		Short: "Repack client files",
		Run: func(cmd *cobra.Command, args []string) {
			repack.Repack(srcClient, dstClient)
		},
	}
	repackCmd.PersistentFlags().StringVarP(&srcClient, "source", "s", "", "Path to Client folder to repack")
	repackCmd.PersistentFlags().StringVarP(&dstClient, "destination", "d", "", "Path to where to save the repacked client")
	rootCmd.AddCommand(repackCmd)

	editCmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit Tibia binary",
		Run: func(cmd *cobra.Command, args []string) {
			edit.Edit(tibiaExe)
		},
	}
	editCmd.PersistentFlags().StringVarP(&tibiaExe, "tibia-exe", "t", getDefaultTibiaExe(), "Path to Tibia executable")

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.toml", "Path to the config file")
	rootCmd.AddCommand(editCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getDefaultTibiaExe() string {
	if runtime.GOOS == "windows" {
		return "client.exe"
	}
	return "client"
}
