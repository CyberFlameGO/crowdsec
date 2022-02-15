#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

LIB="$(dirname "$BATS_TEST_FILENAME")/lib"
load "${LIB}/bats-support/load.bash"
load "${LIB}/bats-assert/load.bash"

declare stderr
CSCLI="${BIN_DIR}/cscli"
CROWDSEC="${BIN_DIR}/crowdsec"

setup_file() {
    echo "# --- $(basename "${BATS_TEST_FILENAME}" .bats)" >&3
    #shellcheck source=tests/bats/lib/assert-crowdsec-not-running.sh
    . "${LIB}/assert-crowdsec-not-running.sh"
}

setup() {
    "${TEST_DIR}/instance-data" load
}

teardown() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

config_disable_agent() {
    yq 'del(.crowdsec_service)' -i "${CONFIG_DIR}/config.yaml"
}

@test "with agent: test without -no-cs flag" {
    run --separate-stderr timeout 1s "${CROWDSEC}"
    # from `man timeout`: If  the  command  times  out,  and --preserve-status is not set, then exit with status 124.
    assert_failure 124
}

@test "no agent: crowdsec LAPI should run (-no-cs flag)" {
    run --separate-stderr timeout 1s "${CROWDSEC}" -no-cs
    assert_failure 124
}

@test "no agent: crowdsec LAPI should run (no crowdsec_service in configuration file)" {
    config_disable_agent
    run --separate-stderr timeout 1s "${CROWDSEC}"
    [[ "$stderr" == *"crowdsec agent is disabled"* ]]
    assert_failure 124
}

@test "no agent: capi status should be ok" {
    config_disable_agent
    "${TEST_DIR}/instance-crowdsec" start
    run --separate-stderr "${CSCLI}" capi status
    [[ "$stderr" == *"You can successfully interact with Central API (CAPI)"* ]]
    assert_success
}

@test "no agent: cscli config show" {
    config_disable_agent
    run --separate-stderr "${CSCLI}" config show -o human
    assert_success
    assert_output --partial "Global:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"

    refute_output --partial "Crowdsec:"
}

@test "no agent: cscli config backup" {
    config_disable_agent
    tempdir=$(mktemp -u)
    run "${CSCLI}" config backup "${tempdir}"
    assert_success
    assert_output --partial "Starting configuration backup"
    run --separate-stderr "${CSCLI}" config backup "${tempdir}"
    assert_failure
    [[ "$stderr" == *"Failed to backup configurations"* ]]
    [[ "$stderr" == *"file exists"* ]]
    rm -rf -- "${tempdir:?}"
}

@test "no agent: lapi status should be ok" {
    config_disable_agent
    "${TEST_DIR}/instance-crowdsec" start
    run --separate-stderr "${CSCLI}" lapi status
    [[ "$stderr" == *"You can successfully interact with Local API (LAPI)"* ]]
    assert_success
}

@test "cscli metrics" {
    config_disable_agent
    "${TEST_DIR}/instance-crowdsec" start
    run --separate-stderr "${CSCLI}" metrics
    assert_success
}
