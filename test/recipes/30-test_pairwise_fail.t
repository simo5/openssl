#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT bldtop_dir srctop_file srctop_dir data_file with);
use OpenSSL::Test::Utils;

BEGIN {
setup("test_pairwise_fail");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => "These tests are unsupported in a non fips build"
    if disabled("fips");

plan tests => 5;
my $provconf = srctop_file("test", "fips-and-base.cnf");

run(test(["fips_version_test", "-config", $provconf, ">=3.1.0"]),
    capture => 1, statusvar => \my $fips_exit);

SKIP: {
    skip "Skip RSA test because of no rsa in this build", 1
        if disabled("rsa");
    ok(run(test(["pairwise_fail_test", "-config", $provconf,
                 "-pairwise", "rsa"])),
       "fips provider rsa keygen pairwise failure test");
}

SKIP: {
    skip "Skip EC test because of no ec in this build", 2
        if disabled("ec");
    with({ exit_checker => sub {my $val = shift; return $val == 134; } },
    sub {
    ok(run(test(["pairwise_fail_test", "-config", $provconf,
                 "-pairwise", "ec"])),
       "fips provider ec keygen pairwise failure test");
    });

    skip "FIPS provider version is too old", 1
        if !$fips_exit;
    with({ exit_checker => sub {my $val = shift; return $val == 134; } },
    sub {
    ok(run(test(["pairwise_fail_test", "-config", $provconf,
                 "-pairwise", "eckat"])),
       "fips provider ec keygen kat failure test");
    });
}

SKIP: {
    skip "Skip DSA tests because of no dsa in this build", 2
        if 1; #if disabled("dsa");
    ok(run(test(["pairwise_fail_test", "-config", $provconf,
                 "-pairwise", "dsa", "-dsaparam", data_file("dsaparam.pem")])),
       "fips provider dsa keygen pairwise failure test");

    skip "FIPS provider version is too old", 1
        if !$fips_exit;
    ok(run(test(["pairwise_fail_test", "-config", $provconf,
                 "-pairwise", "dsakat", "-dsaparam", data_file("dsaparam.pem")])),
       "fips provider dsa keygen kat failure test");
}
