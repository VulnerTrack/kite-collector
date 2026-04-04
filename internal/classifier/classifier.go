package classifier

import "github.com/vulnertrack/kite-collector/internal/model"

// Classifier orchestrates authorization and managed-state classification for
// discovered assets.
type Classifier struct {
	authorizer *Authorizer
	manager    *Manager
}

// New creates a Classifier backed by the given Authorizer and Manager.
func New(authorizer *Authorizer, manager *Manager) *Classifier {
	return &Classifier{
		authorizer: authorizer,
		manager:    manager,
	}
}

// ClassifyAll applies classification to every asset in the slice, updating
// each asset's IsAuthorized and IsManaged fields in place.  The (possibly
// mutated) slice is returned for convenience.
func (c *Classifier) ClassifyAll(assets []model.Asset) []model.Asset {
	for i := range assets {
		c.Classify(&assets[i])
	}
	return assets
}

// Classify sets the IsAuthorized and IsManaged fields on a single asset.
func (c *Classifier) Classify(asset *model.Asset) {
	asset.IsAuthorized = c.authorizer.Authorize(*asset)
	asset.IsManaged = c.manager.Evaluate(*asset)
}
