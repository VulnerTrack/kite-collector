// Package sensors enumerates thermal / fan / voltage / power /
// current sensors exposed by hardware-monitor chips (PCH, NCT,
// IT8728F, ADT74xx, NVIDIA GPU, IPMI BMC). Each Sensor row is
// one (chip, channel) pair.
//
// Per-OS Sources live in build-tagged files. Tests inject a
// fakeSource.
//
// Read-only by intent.
package sensors

import (
	"context"
	"fmt"
	"sort"
	"time"
)

const (
	MaxRows        = 4096
	RecentlyWindow = 5 * time.Minute
)

// SensorType pinned to host_sensors.sensor_type.
type SensorType string

const (
	SensorUnknown  SensorType = "unknown"
	SensorTemp     SensorType = "temp"
	SensorFan      SensorType = "fan"
	SensorVoltage  SensorType = "voltage"
	SensorCurrent  SensorType = "current"
	SensorPower    SensorType = "power"
	SensorEnergy   SensorType = "energy"
	SensorHumidity SensorType = "humidity"
)

// Unit pinned to host_sensors.unit. Values are millis-prefixed
// so we can use int64 and avoid float comparison drift.
type Unit string

const (
	UnitNone         Unit = ""
	UnitMilliCelsius Unit = "milli-celsius"
	UnitRPM          Unit = "rpm"
	UnitMilliVolt    Unit = "milli-volt"
	UnitMilliAmp     Unit = "milli-amp"
	UnitMicroWatt    Unit = "micro-watt"
	UnitMilliJoule   Unit = "milli-joule"
	UnitMilliPercent Unit = "milli-percent"
	UnitUnknown      Unit = "unknown"
)

// Sensor mirrors host_sensors columns.
type Sensor struct {
	Unit          Unit       `json:"unit,omitempty"`
	ChipDriver    string     `json:"chip_driver,omitempty"`
	SensorName    string     `json:"sensor_name"`
	SensorLabel   string     `json:"sensor_label,omitempty"`
	SensorType    SensorType `json:"sensor_type"`
	Chip          string     `json:"chip,omitempty"`
	ValueMillis   int64      `json:"value_millis"`
	MaxMillis     int64      `json:"max_millis,omitempty"`
	CritMillis    int64      `json:"crit_millis,omitempty"`
	IsOverMax     bool       `json:"is_over_max"`
	IsOverCrit    bool       `json:"is_over_crit"`
	IsThermalRisk bool       `json:"is_thermal_risk"`
	IsRecent      bool       `json:"is_recent"`
}

// Source enumerates sensor channels.
type Source interface {
	Enumerate(ctx context.Context) ([]Sensor, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Sensor, error)
}

type collector struct {
	src Source
	now func() time.Time
}

func NewCollector() Collector             { return &collector{src: newSource(), now: time.Now} }
func NewCollectorWith(s Source) Collector { return &collector{src: s, now: time.Now} }
func (c *collector) Name() string         { return "sensors" }

func (c *collector) Collect(ctx context.Context) ([]Sensor, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("sensors enumerate: %w", err)
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	for i := range rows {
		Normalize(&rows[i])
		Annotate(&rows[i])
	}
	SortSensors(rows)
	return rows, nil
}

// Normalize back-fills defaults.
func Normalize(s *Sensor) {
	if s.SensorType == "" {
		s.SensorType = SensorUnknown
	}
	if s.Unit == "" {
		s.Unit = UnitFromType(s.SensorType)
	}
}

// Annotate sets the over-max / over-crit / thermal-risk flags +
// is_recent.
func Annotate(s *Sensor) {
	s.IsRecent = true
	if s.MaxMillis > 0 && s.ValueMillis > s.MaxMillis {
		s.IsOverMax = true
	}
	if s.CritMillis > 0 && s.ValueMillis > s.CritMillis {
		s.IsOverCrit = true
	}
	if s.SensorType == SensorTemp && (s.IsOverMax || s.IsOverCrit) {
		s.IsThermalRisk = true
	}
}

// UnitFromType maps the sensor type to its default unit.
func UnitFromType(t SensorType) Unit {
	switch t {
	case SensorTemp:
		return UnitMilliCelsius
	case SensorFan:
		return UnitRPM
	case SensorVoltage:
		return UnitMilliVolt
	case SensorCurrent:
		return UnitMilliAmp
	case SensorPower:
		return UnitMicroWatt
	case SensorEnergy:
		return UnitMilliJoule
	case SensorHumidity:
		return UnitMilliPercent
	case SensorUnknown:
		return UnitUnknown
	}
	return UnitUnknown
}

// SortSensors returns deterministic ordering by (chip, sensor).
func SortSensors(rs []Sensor) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Chip != rs[j].Chip {
			return rs[i].Chip < rs[j].Chip
		}
		return rs[i].SensorName < rs[j].SensorName
	})
}
