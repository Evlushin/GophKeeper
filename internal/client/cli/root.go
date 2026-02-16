package cli

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/service"
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Short: "CLI client для работы с GophKeeper",
		Long:  `GophKeeper представляет собой клиент-серверную систему, позволяющую пользователю надёжно и безопасно хранить логины, пароли, бинарные данные и прочую приватную информацию.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cmd)
			if err != nil {
				return fmt.Errorf("init viper: %v", err)
			}
			application, err := service.NewContainer(cfg)
			if err != nil {
				return fmt.Errorf("init container: %v", err)
			}
			cmd.SetContext(service.SaveToContext(cmd.Context(), application))
			return nil
		},
	}

	config.BindFlags(rootCmd)

	rootCmd.AddCommand(
		RegisterCmd(),
		LoginCmd(),
		NewSecretCmd(),
	)

	return rootCmd
}

func InitCli(ctx context.Context) error {
	rootCmd := NewRootCmd()
	return rootCmd.ExecuteContext(ctx)
}
