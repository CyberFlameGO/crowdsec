#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

LIB="$(dirname "$BATS_TEST_FILENAME")/lib"
load "${LIB}/bats-support/load.bash"
load "${LIB}/bats-assert/load.bash"

CSCLI="${BIN_DIR}/cscli"

setup_file() {
    echo "# --- $(basename "${BATS_TEST_FILENAME}" .bats)" >&3
    #shellcheck source=tests/bats/lib/assert-crowdsec-not-running.sh
    . "${LIB}/assert-crowdsec-not-running.sh"
}

teardown_file() {
    :
}

setup() {
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
}

teardown() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

@test "can list machines as regular user" {
    run --separate-stderr "${CSCLI}" machines list
    assert_success
}

@test "we have exactly one machine, localhost" {
    run "${CSCLI}" machines list -o json
    assert_success
    [[ $(echo "$output" | jq '. | length') -eq 1 ]]
    [[ $(echo "$output" | jq -r '.[0].machineId') = "githubciXXXXXXXXXXXXXXXXXXXXXXXX" ]]
    [[ $(echo "$output" | jq -r '.[0].isValidated') = "true" ]]
    # it does not have an IP, yet...
    [[ $(echo "$output" | jq -r '.[0].ipAddress') = "null" ]]
    # but it gets one if it speaks to the LAPI
    ${CSCLI} lapi status
    run "${CSCLI}" machines list -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[0].ipAddress') = "127.0.0.1" ]]
}

@test "add a new machine and delete it" {
    run "${CSCLI}" machines add -a -f /dev/null CiTestMachine -o human
    assert_success
    assert_output --partial "Machine 'CiTestMachine' successfully added to the local API"
    assert_output --partial "API credentials dumped to '/dev/null'"

    # we now have two machines
    run "${CSCLI}" machines list -o json
    assert_success
    [[ $(echo "$output" | jq '. | length') -eq 2 ]]
    [[ $(echo "$output" | jq -r '.[-1].machineId') = "CiTestMachine" ]]
    [[ $(echo "$output" | jq -r '.[0].isValidated') = "true" ]]

    # delete the test machine
    run "${CSCLI}" machines delete CiTestMachine -o human
    assert_success
    assert_output --partial "machine 'CiTestMachine' deleted successfully"

    # we now have one machine again
    run "${CSCLI}" machines list -o json
    assert_success
    [[ $(echo "$output" | jq '. | length') -eq 1 ]]
}

@test "register, validate and then remove a machine" {
    run "${CSCLI}" lapi register --machine CiTestMachineRegister -f /dev/null -o human
    assert_success
    assert_output --partial "Successfully registered to Local API (LAPI)"
    assert_output --partial "Local API credentials dumped to '/dev/null'"

    # "the machine is not validated yet" {
    run "${CSCLI}" machines list -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[-1].isValidated') = "null" ]]

    # "validate the machine" {
    run "${CSCLI}" machines validate CiTestMachineRegister -o human
    assert_success
    assert_output --partial "machine 'CiTestMachineRegister' validated successfully"

    # the machine is now validated
    run "${CSCLI}" machines list -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[-1].isValidated') = "true" ]]

    # delete the test machine again
    run "${CSCLI}" machines delete CiTestMachineRegister -o human
    assert_success
    assert_output --partial "machine 'CiTestMachineRegister' deleted successfully"

    # we now have one machine, again
    run "${CSCLI}" machines list -o json
    assert_success
    [[ $(echo "$output" | jq '. | length') -eq 1 ]]
}
