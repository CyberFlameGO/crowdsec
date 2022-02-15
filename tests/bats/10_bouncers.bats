#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

LIB="$(dirname "$BATS_TEST_FILENAME")/lib"
load "${LIB}/bats-support/load.bash"
load "${LIB}/bats-assert/load.bash"

declare stderr
CSCLI="${BIN_DIR}/cscli"

setup_file() {
    echo "# --- $(basename "${BATS_TEST_FILENAME}" .bats)" >&3
    #shellcheck source=tests/bats/lib/assert-crowdsec-not-running.sh
    . "${LIB}/assert-crowdsec-not-running.sh"
}

teardown_file() {
    :
    # TODO remove all the bouncers?
}

setup() {
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
}

teardown() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

@test "there are 0 bouncers" {
    run "${CSCLI}" bouncers list -o json
    assert_success
    assert_output "[]"
}

@test "we can add one bouncer, and delete it" {
    run "${CSCLI}" bouncers add ciTestBouncer
    assert_success
    assert_output --partial "Api key for 'ciTestBouncer':"
    run "${CSCLI}" bouncers delete ciTestBouncer
    assert_success
    run "${CSCLI}" bouncers list -o json
    [[ $(echo "$output" | jq '. | length') -eq 0 ]]
}

@test "we can't add the same bouncer twice" {
    ${CSCLI} bouncers add ciTestBouncer
    run --separate-stderr "${CSCLI}" bouncers add ciTestBouncer -o json
    assert_failure
    [[ $(echo "$stderr" | jq -r '.level') = "fatal" ]]
    [[ $(echo "$stderr" | jq -r '.msg') = "unable to create bouncer: bouncer ciTestBouncer already exists" ]]
    run "${CSCLI}" bouncers list -o json
    [[ $(echo "$output" | jq '. | length') -eq 1 ]]
}

@test "delete the bouncer multiple times, even if it does not exist" {
    ${CSCLI} bouncers add ciTestBouncer
    run "${CSCLI}" bouncers delete ciTestBouncer
    assert_success
    run "${CSCLI}" bouncers delete ciTestBouncer
    assert_success
    run "${CSCLI}" bouncers delete foobarbaz
    assert_success
}
