package main

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/cli"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.InitCli(ctx); err != nil {
		if ctx.Err() != nil {
			_, _ = fmt.Fprintln(os.Stderr, "операция прервана пользователем")
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		}
		os.Exit(1)
	}
}
