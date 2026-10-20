package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

func TestADAttributesFromTags_WireForm(t *testing.T) {
	encoded, err := json.Marshal(map[string]any{
		contract.AttrADSAMAccountName:     "WS01",
		contract.AttrADEnabled:            false,
		contract.AttrADUACFlags:           uint32(4098),
		contract.AttrADLastLogonTimestamp: int64(1776672191),
		contract.AttrADPasswordLastSet:    int64(0),
		contract.AttrADObjectSID:          "",
		contract.AttrADSPNs:               []string{"HOST/ws01", "TERMSRV/ws01"},
		contract.AttrADGroups:             []string{},
		"hostname":                        "ws01",
	})
	require.NoError(t, err)

	got := ADAttributesFromTags(ParseTagObject(string(encoded)))
	assert.Equal(t, map[string]string{
		contract.AttrADSAMAccountName:     "WS01",
		contract.AttrADEnabled:            "false",
		contract.AttrADUACFlags:           "4098",
		contract.AttrADLastLogonTimestamp: "2026-04-20T08:03:11Z",
		contract.AttrADSPNs:               `["HOST/ws01","TERMSRV/ws01"]`,
	}, got, "never-set timestamps, empty strings and empty lists are omitted; non-AD tags ignored")

	var details map[string]string
	require.NoError(t, json.Unmarshal([]byte(BuildEventDetails(Machine{Tags: string(encoded)}, EventMachineDiscovered)), &details))
	assert.Equal(t, "WS01", details[contract.AttrADSAMAccountName])
	assert.Equal(t, "false", details[contract.AttrADEnabled])
}

func TestADAttributesFromTags_NilWithoutADTags(t *testing.T) {
	assert.Nil(t, ADAttributesFromTags(nil))
	assert.Nil(t, ADAttributesFromTags(ParseTagObject(`{"foo":"bar"}`)))

	var evt MachineEvent
	evt.FromMachine(Machine{Hostname: "h", Tags: `{"foo":"bar"}`})
	assert.Nil(t, evt.AD)
}
