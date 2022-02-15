#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:


# XXX TODO split in multile files w/ setup_file, teardown_file

set -u

LIB="$(dirname "$BATS_TEST_FILENAME")/lib"
load "${LIB}/bats-support/load.bash"
load "${LIB}/bats-assert/load.bash"

#declare stderr
export API_KEY
CSCLI="${BIN_DIR}/cscli"


setup_file() {
    echo "# --- $(basename "${BATS_TEST_FILENAME}" .bats)" >&3
    #shellcheck source=tests/bats/lib/assert-crowdsec-not-running.sh
    . "${LIB}/assert-crowdsec-not-running.sh"
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
    API_KEY=$("${CSCLI}" bouncers add testbouncer -o raw)
}

teardown_file() {
    "${TEST_DIR}/instance-crowdsec" stop
}

setup() {
    :
}

teardown() {
    :
}

#----------

CROWDSEC_API_URL="http://localhost:8080"

docurl() {
    URI="$1"
    curl -s -H "X-Api-Key: ${API_KEY}" "${CROWDSEC_API_URL}${URI}"
}

#
# TEST SINGLE IPV4
#

@test 'first decisions list must be empty / cli' {
    run "${CSCLI}" decisions list -o json
    assert_success
    assert_output 'null'
}

@test 'first decisions list must be empty / api' {
    run docurl '/v1/decisions'
    assert_success
    assert_output 'null'
}

@test "adding decision for 1.2.3.4" {
    run "${CSCLI}" decisions add -i '1.2.3.4'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "getting all decisions / cli" {
    run "${CSCLI}" decisions list -o json
    assert_success
    run jq -r '.[0].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '1.2.3.4'
}

# check ip match

@test "getting decision for 1.2.3.4 / cli" {
    run "${CSCLI}" decisions list -i '1.2.3.4' -o json
    assert_success
    run jq -r '.[0].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '1.2.3.4'
}

@test "getting decision for 1.2.3.4 / api" {
    run docurl '/v1/decisions?ip=1.2.3.4'
    assert_success
    run jq -r '.[0].value' <(echo "$output")
    assert_success
    assert_output '1.2.3.4'
}

@test "getting decision for 1.2.3.5 / cli" {
    run "${CSCLI}" decisions list -i '1.2.3.5' -o json
    assert_success
    assert_output 'null'
}

@test "getting decision for 1.2.3.5 / api" {
    run docurl '/v1/decisions?ip=1.2.3.5'
    assert_success
    assert_output 'null'
}

## check outer range match

@test "getting decision for 1.2.3.0/24 / cli" {
    run "${CSCLI}" decisions list -r '1.2.3.0/24' -o json
    assert_success
    assert_output 'null'
}

@test "getting decision for 1.2.3.0/24 / api" {
    run docurl '/v1/decisions?range=1.2.3.0/24'
    assert_success
    assert_output 'null'
}

@test "getting decisions where IP in 1.2.3.0/24 / cli" {
    run "${CSCLI}" decisions list -r '1.2.3.0/24' --contained -o json
    assert_success
    run jq -r '.[0].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '1.2.3.4'
}

@test "getting decisions where IP in 1.2.3.0/24 / api" {
    run docurl '/v1/decisions?range=1.2.3.0/24&contains=false'
    assert_success
    run jq -r '.[0].value' <(echo "$output")
    assert_success
    assert_output '1.2.3.4'
}

#
# TEST IPV4 RANGE
#

@test "adding decision for range 4.4.4.0/24" {
    run "${CSCLI}" decisions add -r '4.4.4.0/24'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "getting all decisions (2) / cli" {
    run "${CSCLI}" decisions list -o json
    assert_success
    run jq -r '.[0].decisions[0].value, .[1].decisions[0].value' <(echo "$output")
    assert_success
    assert_output $'4.4.4.0/24\n1.2.3.4'
}

@test "getting all decisions / api" {
    run docurl '/v1/decisions'
    assert_success
    run jq -r '.[0].value, .[1].value' <(echo "$output")
    assert_success
    assert_output $'1.2.3.4\n4.4.4.0/24'
}

# check ip within/outside of range

@test "getting decisions for ip 4.4.4.3 / cli" {
    run "${CSCLI}" decisions list -i '4.4.4.3' -o json
    assert_success
    run jq -r '.[0].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '4.4.4.0/24'
}

@test "getting decisions for ip 4.4.4.3 / api" {
    run docurl '/v1/decisions?ip=4.4.4.3'
    assert_success
    run jq -r '.[0].value' <(echo "$output")
    assert_success
    assert_output '4.4.4.0/24'
}

@test "getting decisions for ip contained in 4.4.4. / cli" {
    run "${CSCLI}" decisions list -i '4.4.4.4' -o json --contained
    assert_success
    assert_output 'null'
}

@test "getting decisions for ip contained in 4.4.4. / api" {
    run docurl '/v1/decisions?ip=4.4.4.4&contains=false'
    assert_success
    assert_output 'null'
}

@test "getting decisions for ip 5.4.4.3 / cli" {
    run "${CSCLI}" decisions list -i '5.4.4.3' -o json
    assert_success
    assert_output 'null'
}

@test "getting decisions for ip 5.4.4.3 / api" {
    run docurl '/v1/decisions?ip=5.4.4.3'
    assert_success
    assert_output 'null'
}

@test "getting decisions for range 4.4.0.0/1 / cli" {
    run "${CSCLI}" decisions list -r '4.4.0.0/16' -o json
    assert_success
    assert_output 'null'
}

@test "getting decisions for range 4.4.0.0/1 / api" {
    run docurl '/v1/decisions?range=4.4.0.0/16'
    assert_success
    assert_output 'null'
}

@test "getting decisions for ip/range in 4.4.0.0/1 / cli" {
    run "${CSCLI}" decisions list -r '4.4.0.0/16' -o json --contained
    assert_success
    run jq -r '.[0].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '4.4.4.0/24'
}

@test "getting decisions for ip/range in 4.4.0.0/1 / api" {
    run docurl '/v1/decisions?range=4.4.0.0/16&contains=false'
    assert_success
    run jq -r '.[0].value' <(echo "$output")
    assert_success
    assert_output '4.4.4.0/24'
}

# check subrange

@test "getting decisions for range 4.4.4.2/2 / cli" {
    run "${CSCLI}" decisions list -r '4.4.4.2/28' -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '4.4.4.0/24'
}

@test "getting decisions for range 4.4.4.2/2 / api" {
    run docurl '/v1/decisions?range=4.4.4.2/28'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output '4.4.4.0/24'
}

@test "getting decisions for range 4.4.3.2/2 / cli" {
    run "${CSCLI}" decisions list -r '4.4.3.2/28' -o json
    assert_success
    assert_output 'null'
}

@test "getting decisions for range 4.4.3.2/2 / api" {
    run docurl '/v1/decisions?range=4.4.3.2/28'
    assert_success
    assert_output 'null'
}
