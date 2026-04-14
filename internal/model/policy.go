package model

// SeverityRule maps an asset's environment and state to a severity level.
type SeverityRule struct {
	Environment  string             `json:"environment"`
	IsAuthorized AuthorizationState `json:"is_authorized"`
	IsManaged    ManagedState       `json:"is_managed"`
	Severity     Severity           `json:"severity"`
}

// ControlRequirement defines a compliance check that can be executed against assets.
type ControlRequirement struct {
	Name         string `json:"name"`
	CheckCommand string `json:"check_command"`
	Description  string `json:"description"`
}
