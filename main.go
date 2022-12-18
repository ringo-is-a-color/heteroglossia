package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport/http_socks"
	"github.com/ringo-is-a-color/heteroglossia/transport/router"
	"github.com/ringo-is-a-color/heteroglossia/transport/tls_carrier"
	"github.com/ringo-is-a-color/heteroglossia/util/cli"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
	"github.com/ringo-is-a-color/heteroglossia/util/updater"
)

func main() {
	config, err := conf.Parse(cli.Parse().ConfigFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	log.SetVerbose(config.Misc.VerboseLog)

	routeHandler := router.NewHandler(&config.Route, config.Misc.RulesFilesAutoUpdate, config.Outbounds, config.Misc.TLSKeyLog)
	if config.Inbounds.Hg != nil {
		go func() {
			err := tls_carrier.ListenRequests(config.Inbounds.Hg, routeHandler)
			if err != nil {
				log.Fatal("fail to start the hg server", err)
			}
		}()
	}
	if config.Inbounds.HTTPSOCKS != nil {
		go func() {
			err := http_socks.ListenRequests(config.Inbounds.HTTPSOCKS, routeHandler)
			if err != nil {
				log.Fatal("fail to start the HTTP/SOCKS server", err)
			}
		}()
	}

	if config.Misc.HgBinaryAutoUpdate {
		go updater.StartUpdateCron(func() {
			success, latestVersion, err := updater.UpdateHgBinary(routeHandler.HTTPClient)
			if err != nil {
				log.InfoWithError("fail to update the hg binary", err)
			}
			if !success {
				return
			}

			log.Info("update to the latest hg binary successfully", "version", latestVersion)
			err = selfRestart()
			if err != nil {
				log.InfoWithError("fail to restart the new hg binary", err)
			}
		})
	}

	select {}
}

func selfRestart() error {
	log.Info("trying to start the new hg binary")
	executablePath, err := os.Executable()
	if err != nil {
		return errors.WithStack(err)
	}
	// Windows does not support 'syscall.Exec'
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		cmd := exec.Command(executablePath, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		netutil.StopAllListeners()
		err := cmd.Run()
		if err != nil {
			log.Info("fail to start the new hg binary")
			osutil.Exit(1)
		}
		osutil.Exit(0)
	}
	return syscall.Exec(executablePath, os.Args, os.Environ())
}
