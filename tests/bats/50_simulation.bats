#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

FILE="$(basename "${BATS_TEST_FILENAME}" .bats):"
load "${TEST_DIR}/lib/bats-support/load.bash"
load "${TEST_DIR}/lib/bats-assert/load.bash"

# declare stderr
CSCLI="${BIN_DIR}/cscli"
CROWDSEC="${BIN_DIR}/crowdsec"

fake_log() {
    for _ in $(seq 1 10) ; do
        echo "$(LC_ALL=C date '+%b %d %H:%M:%S ')"'sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.174 port 35424'
    done;
}

setup_file() {
    #shellcheck source=../lib/assert-crowdsec-not-running.sh
    . "${TEST_DIR}/lib/assert-crowdsec-not-running.sh"
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
}

teardown_file() {
    "${TEST_DIR}/instance-crowdsec" stop
}

setup() {
    "${CSCLI}" decisions delete --all
}

#----------

@test "$FILE we have one decision" {
    "${CSCLI}" simulation disable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run "${CSCLI}" decisions list -o json
    assert_success
    [[ $(echo "$output" | jq '. | length') -eq 1 ]]
}

@test "$FILE 1.1.1.174 has been banned (exact)" {
    "${CSCLI}" simulation disable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run "${CSCLI}" decisions list -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[].decisions[0].value') = "1.1.1.174" ]]
}

@test "$FILE decision has simulated == false (exact)" {
    "${CSCLI}" simulation disable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run "${CSCLI}" decisions list -o json
    assert_success
    [[ $(echo "$output" | jq -r '.[].decisions[0].simulated') = "false" ]]
}

@test "$FILE simulated scenario, listing non-simulated: expect no decision" {
    "${CSCLI}" simulation enable crowdsecurity/ssh-bf
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run "${CSCLI}" decisions list --no-simu -o json
    assert_success
    assert_output "null"
}

@test "$FILE global simulation, listing non-simulated: expect no decision" {
    "${CSCLI}" simulation disable crowdsecurity/ssh-bf
    "${CSCLI}" simulation enable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run "${CSCLI}" decisions list --no-simu -o json
    assert_success
    assert_output "null"
}
