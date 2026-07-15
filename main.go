package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/opentibiabr/client-editor/appearances"
	"github.com/opentibiabr/client-editor/edit"
	"github.com/opentibiabr/client-editor/repack"
	"github.com/opentibiabr/client-editor/win2mac"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	configFile, tibiaExe, appearancesPath string
	srcClient, dstClient                  string
	srcFile, dstFile                      string
	platform                              string
	compareTibiaExe                       string
	strictEditClientCheck                 bool
	aggressiveEditClientCheck             bool
	sourceTibiaExe                        string
	strictDiagnoseClientCheck             bool
)

var rootCmd = &cobra.Command{
	Use:   "client-editor",
	Short: "Edit or repack Tibia client",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		switch cmd.Name() {
		case "diagnose", "repack", "win2mac":
			return
		}
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
			if err := repack.Repack(srcClient, dstClient, platform); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	repackCmd.PersistentFlags().StringVarP(&srcClient, "source", "s", "", "Path to Client folder to repack")
	repackCmd.PersistentFlags().StringVarP(&dstClient, "destination", "d", "", "Path to where to save the repacked client")
	repackCmd.PersistentFlags().StringVarP(&platform, "platform", "p", "", "Platform to repack for (windows, mac)")
	rootCmd.AddCommand(repackCmd)

	win2macCmd := &cobra.Command{
		Use:   "win2mac",
		Short: "Convert windows asset manifest to mac",
		Run: func(cmd *cobra.Command, args []string) {
			if err := win2mac.Win2Mac(srcFile, dstFile); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	win2macCmd.PersistentFlags().StringVarP(&srcFile, "source", "s", "", "Path to windows assets.json")
	win2macCmd.PersistentFlags().StringVarP(&dstFile, "destination", "d", "", "Path to where to save mac assets.json")
	rootCmd.AddCommand(win2macCmd)

	editCmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit Tibia binary",
		Run: func(cmd *cobra.Command, args []string) {
			edit.Edit(tibiaExe, sourceTibiaExe, strictEditClientCheck, aggressiveEditClientCheck)
		},
	}
	editCmd.PersistentFlags().StringVarP(&tibiaExe, "tibia-exe", "t", getDefaultTibiaExe(), "Path to Tibia executable")
	editCmd.PersistentFlags().StringVar(&sourceTibiaExe, "source-exe", "", "Optional pristine source executable to use as input; defaults to \"client - original.exe\" beside --tibia-exe when present")
	editCmd.PersistentFlags().BoolVar(&aggressiveEditClientCheck, "aggressive", false, "Enable experimental client-check compatibility mode (structural safety checks still apply; keep backup and manual verify)")
	editCmd.PersistentFlags().BoolVar(&strictEditClientCheck, "strict", false, "Fail before export when client-check compatibility is partial, warning, or unsupported")
	editCmd.PersistentFlags().BoolVar(&strictEditClientCheck, "fail-on-partial", false, "Alias for --strict")
	editCmd.PersistentFlags().BoolVar(&strictEditClientCheck, "fail-on-unsupported-client-check", false, "Alias for --strict")
	editCmd.PersistentFlags().BoolVar(&strictEditClientCheck, "fail-on-partial-client-check-patch", false, "Deprecated alias for --strict")
	_ = editCmd.PersistentFlags().MarkDeprecated("fail-on-partial-client-check-patch", "use --strict")
	rootCmd.AddCommand(editCmd)

	diagnoseCmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Diagnose Tibia binary patch compatibility",
		Run: func(cmd *cobra.Command, args []string) {
			edit.Diagnose(tibiaExe, compareTibiaExe, strictDiagnoseClientCheck)
		},
	}
	diagnoseCmd.PersistentFlags().StringVarP(&tibiaExe, "tibia-exe", "t", getDefaultTibiaExe(), "Path to Tibia executable")
	diagnoseCmd.PersistentFlags().StringVar(&compareTibiaExe, "compare-with", "", "Path to a known-good older Tibia executable for comparative diagnosis")
	diagnoseCmd.PersistentFlags().BoolVar(&strictDiagnoseClientCheck, "strict", false, "Exit with an error when client-check compatibility is partial, warning, or unsupported")
	diagnoseCmd.PersistentFlags().BoolVar(&strictDiagnoseClientCheck, "fail-on-partial", false, "Alias for --strict")
	diagnoseCmd.PersistentFlags().BoolVar(&strictDiagnoseClientCheck, "fail-on-unsupported-client-check", false, "Alias for --strict")
	diagnoseCmd.PersistentFlags().BoolVar(&strictDiagnoseClientCheck, "fail-on-partial-client-check-patch", false, "Deprecated alias for --strict")
	_ = diagnoseCmd.PersistentFlags().MarkDeprecated("fail-on-partial-client-check-patch", "use --strict")
	rootCmd.AddCommand(diagnoseCmd)

	appearancesCmd := &cobra.Command{
		Use:   "appearances",
		Short: "Edit Tibia's appearances.dat",
		Run: func(cmd *cobra.Command, args []string) {
			appearances.Appearances(appearancesPath)
		},
	}
	appearancesCmd.PersistentFlags().StringVarP(&appearancesPath, "appearances", "a", "", "Path to appearances.dat")
	rootCmd.AddCommand(appearancesCmd)

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.toml", "Path to the config file")
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
