// Package gpudevices enumerates GPU / accelerator devices on
// the host: discrete GPUs (NVIDIA, AMD, Intel Arc), integrated
// GPUs (Intel UHD, AMD APU, Apple Silicon), and AI accelerators
// (NVIDIA H100, AMD MI300X, Habana Gaudi, Google TPU passthrough).
//
// Per-OS Sources live in build-tagged files. Tests inject a
// fakeSource.
//
// Read-only by intent.
package gpudevices

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 64
	RecentlyWindow = 24 * time.Hour
)

// Vendor pinned to host_gpu_devices.vendor.
type Vendor string

const (
	VendorUnknown     Vendor = "unknown"
	VendorNVIDIA      Vendor = "nvidia"
	VendorAMD         Vendor = "amd"
	VendorIntel       Vendor = "intel"
	VendorApple       Vendor = "apple"
	VendorARM         Vendor = "arm"
	VendorImagination Vendor = "imagination"
	VendorMatrox      Vendor = "matrox"
	VendorVMware      Vendor = "vmware"
	VendorQEMU        Vendor = "qemu"
	VendorGoogle      Vendor = "google"
	VendorAWS         Vendor = "aws"
	VendorHuawei      Vendor = "huawei"
	VendorHabana      Vendor = "habana"
	VendorGraphcore   Vendor = "graphcore"
	VendorCerebras    Vendor = "cerebras"
	VendorSambanova   Vendor = "sambanova"
	VendorOther       Vendor = "other"
)

// AcceleratorType pinned to host_gpu_devices.accelerator_type.
type AcceleratorType string

const (
	TypeUnknown       AcceleratorType = "unknown"
	TypeDiscreteGPU   AcceleratorType = "discrete-gpu"
	TypeIntegratedGPU AcceleratorType = "integrated-gpu"
	TypeVirtualGPU    AcceleratorType = "virtual-gpu"
	TypeAIAccelerator AcceleratorType = "ai-accelerator"
	TypeASIC          AcceleratorType = "asic"
	TypeFPGA          AcceleratorType = "fpga"
	TypeTPU           AcceleratorType = "tpu"
	TypeNPU           AcceleratorType = "npu"
	TypeDPU           AcceleratorType = "dpu"
	TypeOther         AcceleratorType = "other"
)

// Device mirrors host_gpu_devices columns.
type Device struct {
	CardName              string          `json:"card_name"`
	PCIBDF                string          `json:"pci_bdf,omitempty"`
	Vendor                Vendor          `json:"vendor"`
	AcceleratorType       AcceleratorType `json:"accelerator_type"`
	Model                 string          `json:"model,omitempty"`
	Driver                string          `json:"driver,omitempty"`
	VendorID              string          `json:"vendor_id,omitempty"`
	DeviceID              string          `json:"device_id,omitempty"`
	VRAMBytes             int64           `json:"vram_bytes"`
	IsPassthrough         bool            `json:"is_passthrough"`
	HasCompute            bool            `json:"has_compute"`
	HasDisplay            bool            `json:"has_display"`
	IsRenderOnly          bool            `json:"is_render_only"`
	IsRecent              bool            `json:"is_recent"`
	IsVFIOPassthroughRisk bool            `json:"is_vfio_passthrough_risk"`
	IsAIAcceleratorRisk   bool            `json:"is_ai_accelerator_risk"`
}

// Source enumerates GPU devices.
type Source interface {
	Enumerate(ctx context.Context) ([]Device, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Device, error)
}

type collector struct {
	src Source
	now func() time.Time
}

func NewCollector() Collector             { return &collector{src: newSource(), now: time.Now} }
func NewCollectorWith(s Source) Collector { return &collector{src: s, now: time.Now} }
func (c *collector) Name() string         { return "gpudevices" }

func (c *collector) Collect(ctx context.Context) ([]Device, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("gpudevices enumerate: %w", err)
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	for i := range rows {
		Normalize(&rows[i])
		Annotate(&rows[i])
	}
	SortDevices(rows)
	return rows, nil
}

// Normalize back-fills derived vendor + accelerator type.
func Normalize(d *Device) {
	if d.Vendor == "" || d.Vendor == VendorUnknown {
		d.Vendor = VendorFromPCIVendorID(d.VendorID)
	}
	if d.AcceleratorType == "" || d.AcceleratorType == TypeUnknown {
		d.AcceleratorType = DeriveAcceleratorType(d.Vendor, d.Driver, d.Model)
	}
}

// Annotate sets security rollups + is_recent.
func Annotate(d *Device) {
	d.IsRecent = true
	if strings.HasPrefix(d.Driver, "vfio") {
		d.IsPassthrough = true
		d.IsVFIOPassthroughRisk = true
	}
	if d.AcceleratorType == TypeAIAccelerator ||
		d.AcceleratorType == TypeTPU ||
		d.AcceleratorType == TypeNPU {
		d.IsAIAcceleratorRisk = true
	}
}

// VendorFromPCIVendorID maps the PCI Vendor ID (4-hex) to the
// pinned Vendor. Drawn from PCI ID Repository.
func VendorFromPCIVendorID(vid string) Vendor {
	switch strings.ToLower(vid) {
	case "10de":
		return VendorNVIDIA
	case "1002", "1022":
		return VendorAMD
	case "8086":
		return VendorIntel
	case "106b":
		return VendorApple
	case "13b5":
		return VendorARM
	case "1010":
		return VendorImagination
	case "102b":
		return VendorMatrox
	case "15ad":
		return VendorVMware
	case "1234":
		return VendorQEMU
	case "1ae0":
		return VendorGoogle
	case "1d0f":
		return VendorAWS
	case "19e5":
		return VendorHuawei
	case "1da3":
		return VendorHabana
	case "1d05":
		return VendorGraphcore
	}
	if vid == "" {
		return VendorUnknown
	}
	return VendorOther
}

// DeriveAcceleratorType infers a type from vendor + driver + model.
// Heuristic — vendors like NVIDIA span both display GPUs and
// AI accelerators (H100, A100); model name disambiguates.
func DeriveAcceleratorType(v Vendor, driver, model string) AcceleratorType {
	m := strings.ToLower(model)
	d := strings.ToLower(driver)
	switch v {
	case VendorHabana, VendorGraphcore, VendorCerebras, VendorSambanova:
		return TypeAIAccelerator
	case VendorGoogle:
		if strings.Contains(m, "tpu") || strings.Contains(d, "tpu") {
			return TypeTPU
		}
		return TypeAIAccelerator
	case VendorNVIDIA:
		// H100/H200/A100/A40/L40/L4 are AI/HPC accelerators; the
		// presence of "Tesla", "DGX", or any datacenter SKU name
		// is the cleanest signal.
		for _, tag := range []string{"h100", "h200", "a100", "a40", "l40", "l4", "tesla", "dgx", "b100", "b200"} {
			if strings.Contains(m, tag) {
				return TypeAIAccelerator
			}
		}
		return TypeDiscreteGPU
	case VendorAMD:
		for _, tag := range []string{"mi300", "mi250", "mi210", "mi100", "instinct"} {
			if strings.Contains(m, tag) {
				return TypeAIAccelerator
			}
		}
		// Integrated APU detection via driver name "amdgpu" with
		// "raphael", "phoenix", "hawk-point" model strings.
		for _, tag := range []string{"raphael", "phoenix", "hawk-point", "ryzen ai"} {
			if strings.Contains(m, tag) {
				return TypeIntegratedGPU
			}
		}
		return TypeDiscreteGPU
	case VendorIntel:
		if strings.Contains(m, "arc") {
			return TypeDiscreteGPU
		}
		return TypeIntegratedGPU
	case VendorApple:
		return TypeIntegratedGPU
	case VendorARM, VendorImagination:
		return TypeIntegratedGPU
	case VendorVMware, VendorQEMU:
		return TypeVirtualGPU
	case VendorMatrox, VendorAWS, VendorHuawei, VendorOther, VendorUnknown:
		return TypeUnknown
	}
	return TypeUnknown
}

// SortDevices returns deterministic ordering by card name.
func SortDevices(rs []Device) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].CardName < rs[j].CardName })
}
