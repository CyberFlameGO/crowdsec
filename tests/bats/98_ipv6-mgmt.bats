#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

FILE="$(basename "${BATS_TEST_FILENAME}" .bats):"
load "${TEST_DIR}/lib/bats-support/load.bash"
load "${TEST_DIR}/lib/bats-assert/load.bash"

#declare stderr
export API_KEY
CSCLI="${BIN_DIR}/cscli"

setup_file() {
    #shellcheck source=../lib/assert-crowdsec-not-running.sh
    . "${TEST_DIR}/lib/assert-crowdsec-not-running.sh"
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
    API_KEY=$("${CSCLI}" bouncers add testbouncer -o raw)
}

teardown_file() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

CROWDSEC_API_URL="http://localhost:8080"

docurl() {
    URI="$1"
    curl -s -H "X-Api-Key: ${API_KEY}" "${CROWDSEC_API_URL}${URI}"
}

#
# TEST SINGLE IPV6
#

@test "$FILE adding decision for ip 1111:2222:3333:4444:5555:6666:7777:8888" {
    run "${CSCLI}" decisions add -i '1111:2222:3333:4444:5555:6666:7777:8888'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "$FILE getting all decisions / csli" {
    run "${CSCLI}" decisions list -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE getting all decisions / api" {
    run docurl "/v1/decisions"
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:8888 / csli" {
    run "${CSCLI}" decisions list -i '1111:2222:3333:4444:5555:6666:7777:8888' -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:888 / api" {
    run docurl '/v1/decisions?ip=1111:2222:3333:4444:5555:6666:7777:8888'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE getting decisions for ip 1211:2222:3333:4444:5555:6666:7777:8888 / cli" {
    run "${CSCLI}" decisions list -i '1211:2222:3333:4444:5555:6666:7777:8888' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip 1211:2222:3333:4444:5555:6666:7777:888 / api" {
    run docurl '/v1/decisions?ip=1211:2222:3333:4444:5555:6666:7777:8888'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:8887 / cli" {
    run "${CSCLI}" decisions list -i '1111:2222:3333:4444:5555:6666:7777:8887' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:8887 / api" {
    run docurl '/v1/decisions?ip=1111:2222:3333:4444:5555:6666:7777:8887'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/48 / cli" {
    run "${CSCLI}" decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/48' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/48 / api" {
    run docurl '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/48'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip/range 1111:2222:3333:4444:5555:6666:7777:8888/48 / cli" {
    run "${CSCLI}" decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/48' --contained -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE getting decisions for ip/range 1111:2222:3333:4444:5555:6666:7777:8888/48 / api" {
    run docurl '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/48&&contains=false'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/64 / cli" {
    run "${CSCLI}" decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/64' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/64 / api" {
    run docurl '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/64'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64 / cli" {
    run "${CSCLI}" decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/64' -o json --contained
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE getting decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64 / api" {
    run docurl '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/64&&contains=false'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE adding decision for ip 1111:2222:3333:4444:5555:6666:7777:8889" {
    run "${CSCLI}" decisions add -i '1111:2222:3333:4444:5555:6666:7777:8889'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "$FILE / deleting decision for ip 1111:2222:3333:4444:5555:6666:7777:8889" {
    run "${CSCLI}" decisions delete -i '1111:2222:3333:4444:5555:6666:7777:8889'
    assert_success
    assert_output --partial '1 decision(s) deleted'
}

@test "$FILE getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:8889 after delete / cli" {
    run "${CSCLI}" decisions list -i '1111:2222:3333:4444:5555:6666:7777:8889' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE deleting decision for range 1111:2222:3333:4444:5555:6666:7777:8888/64" {
    run "${CSCLI}" decisions delete -r '1111:2222:3333:4444:5555:6666:7777:8888/64' --contained
    assert_success
    assert_output --partial '1 decision(s) deleted'
}

@test "$FILE getting decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64 after delete / cli" {
    run "${CSCLI}" decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/64' -o json --contained
    assert_success
    assert_output 'null'
}

#
# TEST IPV6 RANGE
#

@test "$FILE adding decision for range aaaa:2222:3333:4444::/64" {
    run "${CSCLI}" decisions add -r 'aaaa:2222:3333:4444::/64'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "$FILE getting all decisions (2) / cli" {
    run "${CSCLI}" decisions list -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE getting all decisions (2) / api" {
    run docurl '/v1/decisions'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

# check ip within/out of range

@test "$FILE getting decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888 / cli" {
    run "${CSCLI}" decisions list -i 'aaaa:2222:3333:4444:5555:6666:7777:8888' -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE getting decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888 / api" {
    run docurl '/v1/decisions?ip=aaaa:2222:3333:4444:5555:6666:7777:8888'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE getting decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888 / cli" {
    run "${CSCLI}" decisions list -i 'aaaa:2222:3333:4445:5555:6666:7777:8888' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888 / api" {
    run docurl '/v1/decisions?ip=aaaa:2222:3333:4445:5555:6666:7777:8888'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887 / cli" {
    run "${CSCLI}" decisions list -i 'aaa1:2222:3333:4444:5555:6666:7777:8887' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887 / api" {
    run docurl '/v1/decisions?ip=aaa1:2222:3333:4444:5555:6666:7777:8887'
    assert_success
    assert_output 'null'
}

# check subrange within/out of range

@test "$FILE getting decisions for range aaaa:2222:3333:4444:5555::/80 / cli" {
    run "${CSCLI}" decisions list -r 'aaaa:2222:3333:4444:5555::/80' -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE getting decisions for range aaaa:2222:3333:4444:5555::/80 / api" {
    run docurl '/v1/decisions?range=aaaa:2222:3333:4444:5555::/80'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE getting decisions for range aaaa:2222:3333:4441:5555::/80 / cli" {
    run "${CSCLI}" decisions list -r 'aaaa:2222:3333:4441:5555::/80' -o json
    assert_success
    assert_output 'null'

}

@test "$FILE getting decisions for range aaaa:2222:3333:4441:5555::/80 / api" {
    run docurl '/v1/decisions?range=aaaa:2222:3333:4441:5555::/80'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for range aaa1:2222:3333:4444:5555::/80 / cli" {
    run "${CSCLI}" decisions list -r 'aaa1:2222:3333:4444:5555::/80' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for range aaa1:2222:3333:4444:5555::/80 / api" {
    run docurl '/v1/decisions?range=aaa1:2222:3333:4444:5555::/80'
    assert_success
    assert_output 'null'
}

# check outer range

@test "$FILE getting decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48 / cli" {
    run "${CSCLI}" decisions list -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48 / api" {
    run docurl '/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48 / cli" {
    run "${CSCLI}" decisions list -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' -o json --contained
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE getting decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48 / api" {
    run docurl '/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48&contains=false'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE getting decisions for ip/range in aaaa:2222:3333:4445:5555:6666:7777:8888/48 / cli" {
    run "${CSCLI}" decisions list -r 'aaaa:2222:3333:4445:5555:6666:7777:8888/48' -o json
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip/range in aaaa:2222:3333:4445:5555:6666:7777:8888/48 / api" {
    run docurl '/v1/decisions?range=aaaa:2222:3333:4445:5555:6666:7777:8888/48'
    assert_success
    assert_output 'null'
}

# bbbb:db8:: -> bbbb:db8:0000:0000:0000:7fff:ffff:ffff

@test "$FILE adding decision for range bbbb:db8::/81" {
    run "${CSCLI}" decisions add -r 'bbbb:db8::/81'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "$FILE getting decisions for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff / cli" {
    run "${CSCLI}" decisions list -o json -i 'bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output 'bbbb:db8::/81'
}

@test "$FILE getting decisions for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff / api" {
    run docurl '/v1/decisions?ip=bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    assert_success
    run jq -r '.[].value' <(echo "$output")
    assert_success
    assert_output 'bbbb:db8::/81'
}

@test "$FILE getting decisions for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff / cli" {
    run "${CSCLI}" decisions list -o json -i 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_success
    assert_output 'null'
}

@test "$FILE getting decisions for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff / api" {
    run docurl '/v1/decisions?ip=bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_success
    assert_output 'null'
}

@test "$FILE deleting decision for range aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    run "${CSCLI}" decisions delete -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' --contained
    assert_success
    assert_output --partial '1 decision(s) deleted'
}

@test "$FILE getting decisions for range aaaa:2222:3333:4444::/64 after delete / cli" {
    run "${CSCLI}" decisions list -o json -r 'aaaa:2222:3333:4444::/64'
    assert_success
    assert_output 'null'
}

@test "$FILE adding decision for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff" {
    run "${CSCLI}" decisions add -i 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "$FILE adding decision for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff" {
    run "${CSCLI}" decisions add -i 'bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    assert_success
    assert_output --partial 'Decision successfully added'
}

@test "$FILE deleting decisions for range bbbb:db8::/81" {
    run "${CSCLI}" decisions delete -r 'bbbb:db8::/81' --contained
    assert_success
    assert_output --partial '2 decision(s) deleted'
}

@test "$FILE getting all decisions (3) / cli" {
    run "${CSCLI}" decisions list -o json
    assert_success
    run jq -r '.[].decisions[0].value' <(echo "$output")
    assert_success
    assert_output 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
}
