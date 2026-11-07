// Package collector defines the plugin interface every data source implements.
package collector

import (
	"context"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

type Collector interface {
	Name() string
	// Available reports whether this source can run here (socket present, creds found...).
	Available() bool
	Collect(ctx context.Context) (*graph.Graph, error)
}
