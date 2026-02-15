package internal

import (
	"github.com/sensiblebit/certkit/internal/certstore"
)

// Config holds the runtime application configuration
type Config struct {
	InputPath      string
	Passwords      []string
	Store          *certstore.MemStore
	ExportBundles  bool
	ForceExport    bool
	BundleConfigs  []BundleConfig
	OutDir         string
	IncludeExpired bool
}

// K8sSecret is an alias for certstore.K8sSecret.
type K8sSecret = certstore.K8sSecret

// K8sMetadata is an alias for certstore.K8sMetadata.
type K8sMetadata = certstore.K8sMetadata
