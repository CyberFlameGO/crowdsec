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

@test "$FILE we can list collections" {
    run "${CSCLI}" collections list
    assert_success
}

@test "$FILE there are 2 collections (linux and sshd)" {
    run "${CSCLI}" collections list -o json
    assert_success
    [[ $(echo "$output" | jq '.collections | length') -eq 2 ]]
}

# @test "$FILE cannot install a collection as regular user" {
#   # XXX -o human returns two items, -o json and -o raw return only errors
#   run --separate-stderr cscli collections install crowdsecurity/mysql -o json
#   [ $status -eq 1 ]
#   [[ $(echo $stderr | jq -r '.level') = "fatal" ]]
#   [[ $(echo $stderr | jq '.msg') == *"error while downloading crowdsecurity/mysql"* ]]
#   [[ $(echo $stderr | jq '.msg') == *"permission denied"* ]]
# }

# @test "$FILE can install a collection as root" {
#   run sudo cscli collections install crowdsecurity/mysql -o human
#   [ $status -eq 0 ]
#   assert_output --partial "Enabled crowdsecurity/mysql"
# }

@test "$FILE can install a collection (as a regular user) and remove it" {
    run "${CSCLI}" collections install crowdsecurity/mysql -o human
    assert_success
    assert_output --partial "Enabled crowdsecurity/mysql"
    run "${CSCLI}" collections list -o json
    assert_success
    [[ $(echo "$output" | jq '.collections | length') -eq 3 ]]
    run "${CSCLI}" collections remove crowdsecurity/mysql -o human
    assert_success
    assert_output --partial "Removed symlink [crowdsecurity/mysql]"
}

#@test "$FILE cannot remove a collection as regular user" {
#  run --separate-stderr cscli collections remove crowdsecurity/mysql -o json
#  [ $status -eq 1 ]
#  [[ $(echo $stderr | jq -r '.level') = "fatal" ]]
#  [[ $(echo $stderr | jq '.msg') == *"unable to disable crowdsecurity/mysql"* ]]
#  [[ $(echo $stderr | jq '.msg') == *"permission denied"* ]]
#}
#
#@test "$FILE can remove a collection as root" {
#  run sudo cscli collections remove crowdsecurity/mysql -o human
#  [ $status -eq 0 ]
#  assert_output --partial "Removed symlink [crowdsecurity/mysql]"
#}

@test "$FILE cannot remove a collection twice" {
    run "${CSCLI}" collections install crowdsecurity/mysql -o human
    assert_success
    run --separate-stderr "${CSCLI}" collections remove crowdsecurity/mysql
    assert_success
    run --separate-stderr "${CSCLI}" collections remove crowdsecurity/mysql -o json
    assert_failure
    [[ $(echo "$stderr" | jq -r '.level') = "fatal" ]]
    [[ $(echo "$stderr" | jq '.msg') == *"unable to disable crowdsecurity/mysql"* ]]
    [[ $(echo "$stderr" | jq '.msg') == *"doesn't exist"* ]]
}

