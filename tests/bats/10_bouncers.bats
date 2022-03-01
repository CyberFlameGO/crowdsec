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

@test "$FILE there are 0 bouncers" {
    run "${CSCLI}" bouncers list -o json
    assert_success
    assert_output "[]"
}

@test "$FILE we can add one bouncer, and delete it" {
    run "${CSCLI}" bouncers add ciTestBouncer
    assert_success
    assert_output --partial "Api key for 'ciTestBouncer':"
    run "${CSCLI}" bouncers delete ciTestBouncer
    assert_success
    run "${CSCLI}" bouncers list -o json
    [[ $(echo "$output" | jq '. | length') -eq 0 ]]
}

@test "$FILE we can't add the same bouncer twice" {
    ${CSCLI} bouncers add ciTestBouncer
    run --separate-stderr "${CSCLI}" bouncers add ciTestBouncer -o json
    assert_failure
    [[ $(echo "$stderr" | jq -r '.level') = "fatal" ]]
    [[ $(echo "$stderr" | jq -r '.msg') = "unable to create bouncer: bouncer ciTestBouncer already exists" ]]
    run "${CSCLI}" bouncers list -o json
    [[ $(echo "$output" | jq '. | length') -eq 1 ]]
}

@test "$FILE delete the bouncer multiple times, even if it does not exist" {
    ${CSCLI} bouncers add ciTestBouncer
    run "${CSCLI}" bouncers delete ciTestBouncer
    assert_success
    run "${CSCLI}" bouncers delete ciTestBouncer
    assert_success
    run "${CSCLI}" bouncers delete foobarbaz
    assert_success
}
