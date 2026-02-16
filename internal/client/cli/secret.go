package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/Evlushin/GophKeeper/internal/client/service"
	"golang.org/x/term"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

func NewSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Управление данными",
		Long:  `Команды для просмотра и редактирования данных (требуется авторизация).`,
	}

	// Добавляем подкоманды через их конструкторы
	cmd.AddCommand(
		ListSecretCmd(),
		UpdateSecretCmd(),
		AddSecretCmd(),
		ShowSecretCmd(),
		RemoveSecretCmd(),
	)

	return cmd
}

func ListSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Посмотреть список данных",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := service.FromContext(cmd.Context())

			t, _ := cmd.Flags().GetString("type")

			return s.Secret.List(cmd.Context(), models.ListRequest{
				Type: t,
			})
		},
	}

	config.BindFlags(cmd)

	cmd.Flags().StringP("type", "t", "", "Тип хранимой информации (login_password, binary, card)")

	return cmd
}

func getSecretData(cmd *cobra.Command) (*models.StoreRequest, error) {
	t, _ := cmd.Flags().GetString("type")
	title, _ := cmd.Flags().GetString("title")
	m, _ := cmd.Flags().GetString("metadata")

	if t == "" {
		fmt.Print("Введите тип данных: ")
		_, err := fmt.Scanln(&t)
		if err != nil {
			return nil, fmt.Errorf("ошибка чтения типа данных: %w", err)
		}
	}

	dataType := models.DataType(strings.TrimSpace(t))

	var (
		d         []byte
		reader    io.Reader
		chunkSize int
		filePath  string
		err       error
	)
	switch dataType {
	case models.BinaryData:
		data, _ := cmd.Flags().GetString("data")

		if data != "" {
			d = []byte(strings.TrimSpace(data))
		}

		filePath, _ = cmd.Flags().GetString("file")
		chunkSize, _ = cmd.Flags().GetInt("chunk_size")

		if chunkSize <= 0 {
			chunkSize = 32 * 1024
		}

		switch {
		case filePath != "":

			reader, err = os.Open(filePath)
			if err != nil {
				return nil, fmt.Errorf("ошибка открытия файла: %w", err)
			}

		default:
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				reader = os.Stdin
				d, err = io.ReadAll(reader)
				if err != nil {
					return nil, fmt.Errorf("ошибка чтения из stdin: %w", err)
				}
				reader = nil
			} else {
				fmt.Print("Введите бинарные данные (текст): ")
				var input string
				_, err = fmt.Scanln(&input)
				if err != nil {
					return nil, fmt.Errorf("ошибка чтения данных: %w", err)
				}
				d = []byte(input)
			}
		}

	case models.LoginPassword:
		l, _ := cmd.Flags().GetString("login")
		p, _ := cmd.Flags().GetString("pass")

		if l == "" {
			fmt.Print("Введите логин: ")
			_, err = fmt.Scanln(&l)
			if err != nil {
				return nil, fmt.Errorf("ошибка чтения логина: %w", err)
			}
		}

		if p == "" {
			fmt.Print("Введите пароль: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, fmt.Errorf("ошибка чтения пароля: %w", err)
			}
			p = string(bytePassword)
			fmt.Println()
		}

		cr := models.Credentials{
			Login: l,
			Pass:  p,
		}

		d, err = json.Marshal(cr)
		if err != nil {
			return nil, fmt.Errorf("кодировка в json: %w", err)
		}

	case models.CardData:
		num, _ := cmd.Flags().GetString("number")
		hol, _ := cmd.Flags().GetString("holder")
		exp, _ := cmd.Flags().GetString("expiry")
		cvv, _ := cmd.Flags().GetString("cvv")
		bank, _ := cmd.Flags().GetString("bank")

		card := models.Card{
			Number:     num,
			Holder:     hol,
			ExpiryDate: exp,
			CVV:        cvv,
			Bank:       bank,
		}

		d, err = json.Marshal(card)
		if err != nil {
			return nil, fmt.Errorf("кодировка в json: %w", err)
		}

	default:
		return nil, errors.New("тип данных не найден")
	}

	return &models.StoreRequest{
		SecretData: models.SecretData{
			DataType: dataType,
			Title:    strings.TrimSpace(title),
			Metadata: strings.TrimSpace(m),
			FilePath: filePath,
			Data:     d,
		},
		Reader:    reader,
		ChunkSize: chunkSize,
	}, nil
}

func UpdateSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Обновить данные",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := service.FromContext(cmd.Context())

			id, _ := cmd.Flags().GetString("id")

			if id == "" {
				fmt.Print("Введите ID: ")
				_, err := fmt.Scanln(&id)
				if err != nil {
					return fmt.Errorf("ошибка чтения ID: %w", err)
				}
			}

			secret, err := getSecretData(cmd)
			if err != nil {
				return fmt.Errorf("ошибка получения секрета: %w", err)
			}

			return s.Secret.Update(cmd.Context(), models.UpdateRequest{
				StoreRequest: models.StoreRequest{
					SecretData: models.SecretData{
						DataType: secret.DataType,
						Title:    secret.Title,
						Metadata: secret.Metadata,
						FilePath: secret.FilePath,
						Data:     secret.Data,
					},
					Reader:    secret.Reader,
					ChunkSize: secret.ChunkSize,
				},
				ID: strings.TrimSpace(id),
			})
		},
	}

	cmd.Flags().StringP("id", "", "", "id секрета")
	getFlagsString(cmd)

	return cmd
}

func getFlagsString(cmd *cobra.Command) {
	config.BindFlags(cmd)

	cmd.Flags().StringP("type", "t", "", "Тип секрета (login_password, binary, card)")
	cmd.Flags().StringP("title", "", "", "Название секрета")
	cmd.Flags().StringP("metadata", "m", "", "Метаданные секрета")

	cmd.Flags().StringP("data", "", "", "Строковые данные")
	cmd.Flags().StringP("file", "", "", "Путь к файлу")
	cmd.Flags().StringP("chunk_size", "", "", "Разер куска для отправки больших данных в байтах")

	cmd.Flags().StringP("login", "l", "", "Логин нового пользователя (можно ввести интерактивно)")
	cmd.Flags().StringP("pass", "p", "", "Пароль нового пользователя (рекомендуется интерактивный ввод)")

	cmd.Flags().StringP("number", "", "", "Номер карты")
	cmd.Flags().StringP("holder", "", "", "Владелец карты")
	cmd.Flags().StringP("expiry", "", "", "Срок действия")
	cmd.Flags().StringP("cvv", "", "", "CVV карты")
	cmd.Flags().StringP("bank", "", "", "Банк")
}

func AddSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Добавить новые данные",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := service.FromContext(cmd.Context())

			secret, err := getSecretData(cmd)
			if err != nil {
				return fmt.Errorf("ошибка получения секрета: %w", err)
			}

			return s.Secret.Store(cmd.Context(), *secret)
		},
	}

	getFlagsString(cmd)

	return cmd
}

func ShowSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Просмотреть данные",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := service.FromContext(cmd.Context())

			id, _ := cmd.Flags().GetString("id")

			if id == "" {
				fmt.Print("Введите ID: ")
				_, err := fmt.Scanln(&id)
				if err != nil {
					return fmt.Errorf("ошибка чтения ID: %w", err)
				}
			}

			if id == "" {
				return errors.New("id обязателен")
			}

			return s.Secret.Show(cmd.Context(), models.ShowRequest{
				ID: strings.TrimSpace(id),
			})
		},
	}

	config.BindFlags(cmd)

	return cmd
}

func RemoveSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Удалить данные",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := service.FromContext(cmd.Context())

			id, _ := cmd.Flags().GetString("id")

			if id == "" {
				fmt.Print("Введите ID: ")
				_, err := fmt.Scanln(&id)
				if err != nil {
					return fmt.Errorf("ошибка чтения ID: %w", err)
				}
			}

			if id == "" {
				return errors.New("id обязателен")
			}

			return s.Secret.Delete(cmd.Context(), models.DeleteRequest{
				ID: strings.TrimSpace(id),
			})
		},
	}

	config.BindFlags(cmd)

	return cmd
}
