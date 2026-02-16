package cli

import (
	"errors"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/Evlushin/GophKeeper/internal/client/service"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"syscall"
)

func LoginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Авторизация",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := service.FromContext(cmd.Context())

			l, _ := cmd.Flags().GetString("login")
			p, _ := cmd.Flags().GetString("password")

			if l == "" {
				fmt.Print("Введите логин: ")
				_, err := fmt.Scanln(&l)
				if err != nil {
					return fmt.Errorf("ошибка чтения логина: %w", err)
				}
			}

			if p == "" {
				fmt.Print("Введите пароль: ")
				bytePassword, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return fmt.Errorf("ошибка чтения пароля: %w", err)
				}
				p = string(bytePassword)
				fmt.Println()
			}

			if l == "" || p == "" {
				return errors.New("логин и пароль обязательны")
			}

			return s.Auth.Login(cmd.Context(), models.LoginRequest{
				Login:    l,
				Password: p,
			})
		},
	}

	config.BindFlags(cmd)

	cmd.Flags().StringP("login", "l", "", "Логин нового пользователя (можно ввести интерактивно)")
	cmd.Flags().StringP("password", "p", "", "Пароль нового пользователя (рекомендуется интерактивный ввод)")

	return cmd
}
