#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

FILE="$(basename "${BATS_TEST_FILENAME}" .bats):"
load "${TEST_DIR}/lib/bats-support/load.bash"
load "${TEST_DIR}/lib/bats-assert/load.bash"

declare stderr
CSCLI="${BIN_DIR}/cscli"

setup_file() {
    #shellcheck source=../lib/assert-crowdsec-not-running.sh
    . "${TEST_DIR}/lib/assert-crowdsec-not-running.sh"
}

setup() {
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
}

teardown() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

@test "$FILE cscli version" {
    run "${CSCLI}" version
    assert_success
    assert_output --partial "version:"
    assert_output --partial "Codename:"
    assert_output --partial "BuildDate:"
    assert_output --partial "GoVersion:"
    assert_output --partial "Platform:"
    assert_output --partial "Constraint_parser:"
    assert_output --partial "Constraint_scenario:"
    assert_output --partial "Constraint_api:"
    assert_output --partial "Constraint_acquis:"
}

#@test "$FILE cscli alerts list: at startup returns at least one entry: community pull" {
#   skip "XXX TODO: community blocklist is not received because reasons"
#   sleep 40
#   run ${CSCLI} alerts list -o json
#   assert_success
#   refute_output "null"
#   refute_output "[]"
#   refute_output ""
#   #XXX check there's at least one item
#}


@test "$FILE cscli capi status" {
    run "${CSCLI}" capi status
    assert_success
    assert_output --partial "Loaded credentials from"
    assert_output --partial "Trying to authenticate with username"
    assert_output --partial " on https://api.crowdsec.net/"
    assert_output --partial "You can successfully interact with Central API (CAPI)"
}

@test "$FILE cscli config show -o human" {
    run "${CSCLI}" config show -o human
    assert_success
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"
}

@test "$FILE cscli config show -o json" {
    run "${CSCLI}" config show -o json
    assert_success
    assert_output --partial '"API":'
    assert_output --partial '"Common":'
    assert_output --partial '"ConfigPaths":'
    assert_output --partial '"Crowdsec":'
    assert_output --partial '"Cscli":'
    assert_output --partial '"DbConfig":'
    assert_output --partial '"Hub":'
    assert_output --partial '"PluginConfig":'
    assert_output --partial '"Prometheus":'
}

@test "$FILE cscli config show -o raw" {
    run "${CSCLI}" config show -o raw
    assert_success
    assert_line "api:"
    assert_line "common:"
    assert_line "config_paths:"
    assert_line "crowdsec_service:"
    assert_line "cscli:"
    assert_line "db_config:"
    assert_line "plugin_config:"
    assert_line "prometheus:"
}

@test "$FILE cscli config show --key" {
    run "${CSCLI}" config show --key Config.API.Server.ListenURI
    assert_success
    assert_output "127.0.0.1:8080"
}

@test "$FILE cscli config backup" {
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

@test "$FILE cscli lapi status" {
    run --separate-stderr "${CSCLI}" lapi status
    assert_success
    [[ "$stderr" == *"Loaded credentials from"* ]]
    [[ "$stderr" == *"Trying to authenticate with username"* ]]
    [[ "$stderr" == *" on http://127.0.0.1:8080/"* ]]
    [[ "$stderr" == *"You can successfully interact with Local API (LAPI)"* ]]
}

@test "$FILE cscli metrics" {
    sleep 1
    run --separate-stderr "${CSCLI}" metrics
    assert_success
    [[ "$stderr" == *"Local Api Metrics:"* ]]
    assert_output --partial "ROUTE"
    assert_output --partial '/v1/watchers/login'
}
