package containers

import "context"

// NewContainerdCollector returns a stub Containerd collector.
//
// TODO(cdms-iter): wire the containerd CRI API (containerd's grpc client
// or `ctr` shell-out). Containerd is the Kubernetes node runtime so it
// matters in production fleets, but the wiring is heavier than the
// Docker Engine API (separate gRPC client, namespaces, sandboxes).
// Stub keeps the multi-runtime collector chain typeable while we ship
// the Docker/Podman path first.
func NewContainerdCollector() Collector { return containerdStub{} }

type containerdStub struct{}

func (containerdStub) Name() string { return "containerd-stub" }

func (containerdStub) Collect(_ context.Context) ([]Container, error) {
	return []Container{}, nil
}
