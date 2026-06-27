package sensors

import (
	"context"
	"errors"
	"testing"
)

func TestUnitFromType(t *testing.T) {
	cases := map[SensorType]Unit{
		SensorTemp:     UnitMilliCelsius,
		SensorFan:      UnitRPM,
		SensorVoltage:  UnitMilliVolt,
		SensorCurrent:  UnitMilliAmp,
		SensorPower:    UnitMicroWatt,
		SensorEnergy:   UnitMilliJoule,
		SensorHumidity: UnitMilliPercent,
		SensorUnknown:  UnitUnknown,
	}
	for in, want := range cases {
		if got := UnitFromType(in); got != want {
			t.Fatalf("UnitFromType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAnnotateOverMaxAndThermalRisk(t *testing.T) {
	s := Sensor{
		SensorType:  SensorTemp,
		ValueMillis: 95000, // 95C
		MaxMillis:   90000,
		CritMillis:  100000,
	}
	Annotate(&s)
	if !s.IsOverMax {
		t.Fatal("over max not flagged")
	}
	if s.IsOverCrit {
		t.Fatal("under crit must NOT flag over_crit")
	}
	if !s.IsThermalRisk {
		t.Fatal("over_max temp must flag thermal risk")
	}
}

func TestAnnotateOverCrit(t *testing.T) {
	s := Sensor{SensorType: SensorTemp, ValueMillis: 105000, CritMillis: 100000}
	Annotate(&s)
	if !s.IsOverCrit {
		t.Fatal("over crit not flagged")
	}
	if !s.IsThermalRisk {
		t.Fatal("over crit temp must flag thermal risk")
	}
}

func TestAnnotateNonTempDoesNotFlagThermal(t *testing.T) {
	s := Sensor{SensorType: SensorFan, ValueMillis: 5000, MaxMillis: 4000}
	Annotate(&s)
	if !s.IsOverMax {
		t.Fatal("fan over max should flag IsOverMax")
	}
	if s.IsThermalRisk {
		t.Fatal("non-temp over max must NOT flag thermal risk")
	}
}

func TestSortSensorsDeterministic(t *testing.T) {
	rs := []Sensor{
		{Chip: "nct6798", SensorName: "temp2"},
		{Chip: "coretemp", SensorName: "temp1"},
		{Chip: "coretemp", SensorName: "temp0"},
	}
	SortSensors(rs)
	if rs[0].Chip != "coretemp" || rs[0].SensorName != "temp0" {
		t.Fatalf("sort drift: %+v", rs)
	}
}

type fakeSource struct {
	err  error
	rows []Sensor
}

func (f fakeSource) Enumerate(_ context.Context) ([]Sensor, error) { return f.rows, f.err }

func TestCollectorPipeline(t *testing.T) {
	rows := []Sensor{{
		Chip: "coretemp", SensorName: "temp1", SensorType: SensorTemp,
		ValueMillis: 91000, MaxMillis: 90000,
	}}
	got, err := NewCollectorWith(fakeSource{rows: rows}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got[0].Unit != UnitMilliCelsius {
		t.Fatalf("unit=%q", got[0].Unit)
	}
	if !got[0].IsThermalRisk {
		t.Fatalf("thermal risk missing: %+v", got[0])
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("sensors fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "sensors" {
		t.Fatal("name drift")
	}
}
