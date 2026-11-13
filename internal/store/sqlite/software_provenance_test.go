package sqlite

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestSoftwareProvenanceSurvivesBothPersistencePaths(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	m := makeMachine("provenance-host", model.MachineTypeServer)
	sw := model.InstalledSoftware{
		ID: uuid.Must(uuid.NewV7()), SoftwareName: "File::Spec::Unix", Version: "3.88", PackageManager: "cpan",
		SourcePackage: "fixture-source", SourceVersion: "2.0-1",
		PackageOwner: &model.SoftwarePackageOwner{Name: "perl-base", Version: "5.38.2-3", PackageManager: "dpkg", SourcePackage: "perl", SourceVersion: "5.38.2-3", File: "/usr/lib/perl/File/Spec/Unix.pm", Evidence: "dpkg-query-search"},
	}
	m.Software = []model.InstalledSoftware{sw}
	_, _, err := s.UpsertMachines(ctx, []model.Machine{m})
	require.NoError(t, err)
	for _, upsert := range []bool{false, true} {
		if upsert {
			require.NoError(t, s.UpsertSoftware(ctx, m.ID, []model.InstalledSoftware{sw}))
		}
		got, err := s.ListSoftware(ctx, m.ID)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, sw.PackageOwner, got[0].PackageOwner)
		require.Equal(t, sw.SourcePackage, got[0].SourcePackage)
		require.Equal(t, sw.SourceVersion, got[0].SourceVersion)
		require.Equal(t, "3.88", got[0].Version)
	}
}
