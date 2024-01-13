package conf

import (
	"encoding/json"
	stdErrors "errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

var validate = validator.New()

func init() {
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := fld.Tag.Get("json")
		if name == "" {
			return strings.ToLower(fld.Name)
		}
		return name
	})
}

func Parse(configFilePath string) (*Config, error) {
	bs, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "error")
	}

	config := &Config{}
	// default to direct for Final field
	config.Route.Final = "direct"
	config.Misc.ProfilingPort = defaultProfilingPort
	err = json.Unmarshal(bs, &config)
	if err != nil {
		return nil, errors.Wrapf(err, "error: %v", configFilePath)
	}

	err = config.Route.Rules.SetupRulesData()
	if err != nil {
		return nil, err
	}

	err = validate.Struct(config)
	if err != nil {
		var errs validator.ValidationErrors
		if stdErrors.As(err, &errs) {
			if len(errs) > 0 {
				validatedError := errors.Newf("error: fail to parse the config file %v", configFilePath)
				for _, err := range errs {
					fieldName := err.Namespace()[strings.Index(err.Namespace(), ".")+1:]
					validatedError = errors.Join(validatedError, errors.Newf("  the '%v' field should be '%v'", fieldName, err.ActualTag()))
				}
				return nil, validatedError
			}
		}
	}
	resolveAllFilePathsToConfigFolder(config, filepath.Dir(configFilePath))
	return config, nil
}

func resolveAllFilePathsToConfigFolder(config *Config, configFileFolder string) {
	hg := config.Inbounds.Hg
	if hg != nil {
		tlsCertKeyPair := config.Inbounds.Hg.TLSCertKeyPair
		if tlsCertKeyPair != nil {
			tlsCertKeyPair.CertFile = resolveTo(tlsCertKeyPair.CertFile, configFileFolder)
			tlsCertKeyPair.KeyFile = resolveTo(tlsCertKeyPair.KeyFile, configFileFolder)
		}
		if hg.TLSBadAuthFallbackSiteDir != "" {
			hg.TLSBadAuthFallbackSiteDir = resolveTo(hg.TLSBadAuthFallbackSiteDir, configFileFolder)
		}
	}
	for _, v := range config.Outbounds {
		if v.TLSCertFile != "" {
			v.TLSCertFile = resolveTo(v.TLSCertFile, configFileFolder)
		}
	}
}

func resolveTo(relativePath string, basePath string) string {
	if filepath.IsAbs(relativePath) {
		return relativePath
	}
	return filepath.Join(basePath, relativePath)
}
