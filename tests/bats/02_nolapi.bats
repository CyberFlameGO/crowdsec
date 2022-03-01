#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

FILE="$(basename "${BATS_TEST_FILENAME}" .bats):"
load "${TEST_DIR}/lib/bats-support/load.bash"
load "${TEST_DIR}/lib/bats-assert/load.bash"

declare stderr
CSCLI="${BIN_DIR}/cscli"
CROWDSEC="${BIN_DIR}/crowdsec"

setup_file() {
    #shellcheck source=../lib/assert-crowdsec-not-running.sh
    . "${TEST_DIR}/lib/assert-crowdsec-not-running.sh"
}

setup() {
    # always reset config and data, but run the daemon only if one test requires it
    "${TEST_DIR}/instance-data" load
}

teardown() {
    # the crowdsec daemon can be left running by a tests which ran it, if the test failed
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

@test "$FILE test without -no-api flag" {
    run --separate-stderr timeout 1s "${CROWDSEC}"
    # from `man timeout`: If  the  command  times  out,  and --preserve-status is not set, then exit with status 124.
    assert_failure 124
}

@test "$FILE crowdsec should not run without LAPI (-no-api flag)" {
    run --separate-stderr timeout 1s "${CROWDSEC}" -no-api
    assert_failure 1
}

@test "$FILE crowdsec should not run without LAPI (no api.server in configuration file)" {
    yq 'del(.api.server)' -i "${CONFIG_DIR}/config.yaml"
    run --separate-stderr timeout 1s "${CROWDSEC}"
    [[ "$stderr" == *"crowdsec local API is disabled"* ]]
    assert_failure 1
}

@test "$FILE capi status shouldn't be ok without api.server" {
    yq 'del(.api.server)' -i "${CONFIG_DIR}/config.yaml"
    run --separate-stderr "${CSCLI}" capi status
    [[ "$stderr" == *"Local API is disabled, please run this command on the local API machine"* ]]
    assert_failure 1
}

@test "$FILE cscli config show -o human" {
    yq 'del(.api.server)' -i "${CONFIG_DIR}/config.yaml"
    run "${CSCLI}" config show -o human
    assert_success
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    refute_output --partial "Local API Server:"
}

@test "$FILE cscli config backup" {
    yq 'del(.api.server)' -i "${CONFIG_DIR}/config.yaml"
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

@test "$FILE lapi status shouldn't be ok without api.server" {
    yq 'del(.api.server)' -i "${CONFIG_DIR}/config.yaml"
    run --separate-stderr "${CSCLI}" lapi status
    # XXX which message do we expect?
    # echo $stderr >&3
    # [[ "$stderr" == *"Local API is disabled, please run this command on the local API machine"* ]]
    assert_failure 1
}

@test "$FILE cscli metrics" {
    skip
    yq 'del(.api.server)' -i "${CONFIG_DIR}/config.yaml"
    "${TEST_DIR}/instance-crowdsec" start
    run --separate-stderr "${CSCLI}" metrics
    assert_success
    [[ "$stderr" != *"Local Api Metrics:"* ]]
    # XXX output is empty ?
    assert_output --partial "ROUTE"
    assert_output --partial "/v1/watchers/login"
}
