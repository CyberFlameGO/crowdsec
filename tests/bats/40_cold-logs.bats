#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

LIB="$(dirname "$BATS_TEST_FILENAME")/lib"
load "${LIB}/bats-support/load.bash"
load "${LIB}/bats-assert/load.bash"

#declare stderr
CSCLI="${BIN_DIR}/cscli"
CROWDSEC="${BIN_DIR}/crowdsec"

fake_log() {
    for _ in $(seq 1 6) ; do
        echo "$(LC_ALL=C date '+%b %d %H:%M:%S ')"'sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.172 port 35424'
    done;
}

setup_file() {
    echo "# --- $(basename "${BATS_TEST_FILENAME}" .bats)" >&3
    #shellcheck source=tests/bats/lib/assert-crowdsec-not-running.sh
    . "${LIB}/assert-crowdsec-not-running.sh"
    # we reset config and data, and only run the daemon once for all the tests in this file
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    # we could also keep it running for all the tests, but the
    # check in "assert-crowdsec-not-running.sh" is run AFTER setup_file
    "${TEST_DIR}/instance-crowdsec" stop
}

teardown_file() {
    :
}

setup() {
    "${TEST_DIR}/instance-crowdsec" start
}

teardown() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

@test "we have one decision" {
    run "${CSCLI}" decisions list -o json
    assert_success
    [[ $(echo "$output" | jq '. | length') -eq 1 ]]
}

@test "1.1.1.172 has been banned" {
    run "${CSCLI}" decisions list -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[].decisions[0].value') = "1.1.1.172" ]]
}

@test "1.1.1.172 has been banned (range/contained: -r 1.1.1.0/24 --contained)" {
    run "${CSCLI}" decisions list -r 1.1.1.0/24 --contained -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[].decisions[0].value') = "1.1.1.172" ]]
}

@test "1.1.1.172 has not been banned (range/NOT-contained: -r 1.1.2.0/24)" {
    run "${CSCLI}" decisions list -r 1.1.2.0/24 -o json
    assert_success
    assert_output "null"
}

@test "1.1.1.172 has been banned (exact: -i 1.1.1.172)" {
    run "${CSCLI}" decisions list -i 1.1.1.172 -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[].decisions[0].value') = "1.1.1.172" ]]
}

@test "1.1.1.173 has not been banned (exact: -i 1.1.1.173)" {
    run "${CSCLI}" decisions list -i 1.1.1.173 -o json
    assert_success
    assert_output "null"
}
