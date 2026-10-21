package azure

import rego.v1

default allow := false

allow if {
	pcr_bank_ok
	tpm_evidence_ok
	runtime_claims_ok
	hardware_claims_ok
}

is_hex(s, n) if {
	is_string(s)
	count(s) == n
	regex.match(`^[0-9a-fA-F]+$`, s)
}

byte_array(xs) if {
	is_array(xs)
	count(xs) > 0
	count([x | x := xs[_]; not is_number(x)]) == 0
	count([x | x := xs[_]; x < 0]) == 0
	count([x | x := xs[_]; x > 255]) == 0
}

expected_pcr_ids := {
	0, 1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23,
}

pcr_bank_ok if {
	is_object(input.pcr_bank)
	is_object(input.pcr_bank.pcr_list)
	count(input.pcr_bank.pcr_list) == 24
	count([id | expected_pcr_ids[id]; not input.pcr_bank.pcr_list[id]]) == 0
	count([id | pcr := input.pcr_bank.pcr_list[id]; not is_hex(pcr.digest, 64)]) == 0
}

tpm_evidence_ok if {
	byte_array(input.tpm_evidence.qualified_signer)
	is_hex(input.tpm_evidence.extra_data, 64)

	input.tpm_evidence.clock_info.safe == true
	is_number(input.tpm_evidence.clock_info.clock)
	input.tpm_evidence.clock_info.clock >= 0
	is_number(input.tpm_evidence.clock_info.reset_count)
	input.tpm_evidence.clock_info.reset_count >= 0
	is_number(input.tpm_evidence.clock_info.restart_count)
	input.tpm_evidence.clock_info.restart_count >= 0

	is_number(input.tpm_evidence.firmware_version)
}

runtime_claims_ok if {
	count(input.runtime_claims.keys) >= 1
	count([i | key := input.runtime_claims.keys[i]; not valid_jwk(key)]) == 0
	vm_config_ok
	is_hex(input.runtime_claims["user-data"], 128)
}

valid_jwk(key) if {
	is_string(key.kid)
	key.kid != ""
	key.kty == "RSA"
	is_string(key.e)
	key.e != ""
	is_string(key.n)
	key.n != ""
	is_array(key.key_ops)
	count(key.key_ops) > 0
}

vm_config_ok if {
	cfg := input.runtime_claims["vm-configuration"]

	cfg["secure-boot"] == true
	cfg["tpm-enabled"] == true

	# cfg["console-enabled"] == false
	is_boolean(cfg["tpm-persisted"])

	is_string(cfg.vmUniqueId)
	cfg.vmUniqueId != ""
}

hardware_claims_ok if {
	input.hardware_claims.type == "Sev"
	is_object(input.hardware_claims.report)
	data.sev.allow with input as input.hardware_claims.report
}

hardware_claims_ok if {
	input.hardware_claims.type == "Tdx"
	is_object(input.hardware_claims.report)
	data.tdx.allow with input as input.hardware_claims.report
}
