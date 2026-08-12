// Canary signatures for the kite osquery simulation.
//
// These rules exist to prove the YARA integration surface works end to end —
// the on-demand `yara` table and the event-driven `yara_events` table — not to
// detect real malware. The checks battery plants a file containing the marker
// string below and asserts osquery reports a match (and that a clean file does
// NOT match, guarding against a rules-file parse failure that would silently
// match everything or nothing).

rule kite_sim_canary
{
    meta:
        description = "Matches the marker string the checks battery plants"
        author = "kite osquery sim"

    strings:
        $marker = "KITE-OSQUERY-SIM-YARA-CANARY"

    condition:
        $marker
}

rule kite_sim_hex_canary
{
    meta:
        description = "Second rule so multi-rule sigfiles are exercised"

    strings:
        // "KITEHEX" in hex — proves hex-string rules compile in this build.
        $hex = { 4B 49 54 45 48 45 58 }

    condition:
        $hex
}
