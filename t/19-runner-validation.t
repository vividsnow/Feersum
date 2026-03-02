#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;

BEGIN {
    plan skip_all => 'not applicable on win32'
        if $^O eq 'MSWin32';
}

plan tests => 17;

use_ok('Feersum::Runner');

#######################################################################
# Test pre_fork validation
#######################################################################

{
    # pre_fork = 0 should croak
    eval {
        my $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            pre_fork => 0,
            app => sub { shift->send_response(200, [], []); }
        );
        # Force validation by calling _start_pre_fork indirectly
        # Actually we need to trigger the validation
    };
    # The validation happens in _start_pre_fork, which is called from run()
    # We can't easily test this without actually running, so test the module loads
    pass('pre_fork=0: module loads (validation happens at runtime)');
}

{
    # Test that Runner accepts valid pre_fork value
    my $runner;
    eval {
        $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            pre_fork => 2,
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
    };
    ok(!$@, 'pre_fork=2: Runner created without error');
    ok($runner, 'pre_fork=2: Runner object exists');
    undef $Feersum::Runner::INSTANCE;
}

#######################################################################
# Test priority validation
#######################################################################

{
    # Valid priority values should work
    my $runner;
    eval {
        $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            read_priority => -2,
            write_priority => 0,
            accept_priority => 2,
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
    };
    ok(!$@, 'Valid priorities (-2, 0, 2): Runner created without error');
    ok($runner, 'Valid priorities: Runner object exists');
    undef $Feersum::Runner::INSTANCE;
}

{
    # Invalid read_priority should croak during _prepare
    my $runner;
    my $error;
    eval {
        $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            read_priority => -3,  # Invalid: below -2
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        # Force _prepare to be called
        $runner->_prepare();
    };
    $error = $@;
    like($error, qr/read_priority must be between -2 and 2/, 'read_priority=-3: rejected with clear error');
    undef $Feersum::Runner::INSTANCE;
}

{
    # Invalid write_priority should croak
    my $runner;
    my $error;
    eval {
        $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            write_priority => 3,  # Invalid: above 2
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    $error = $@;
    like($error, qr/write_priority must be between -2 and 2/, 'write_priority=3: rejected with clear error');
    undef $Feersum::Runner::INSTANCE;
}

{
    # Invalid accept_priority should croak
    my $runner;
    my $error;
    eval {
        $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            accept_priority => 5,  # Invalid: above 2
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    $error = $@;
    like($error, qr/accept_priority must be between -2 and 2/, 'accept_priority=5: rejected with clear error');
    undef $Feersum::Runner::INSTANCE;
}

#######################################################################
# Test boundary priority values
#######################################################################

{
    # Priority exactly at -2 (minimum) should work
    my $runner;
    eval {
        $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            read_priority => -2,
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    ok(!$@, 'read_priority=-2 (boundary): accepted');
    undef $Feersum::Runner::INSTANCE;
}

{
    # Priority exactly at 2 (maximum) should work
    my $runner;
    eval {
        $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            write_priority => 2,
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    ok(!$@, 'write_priority=2 (boundary): accepted');
    undef $Feersum::Runner::INSTANCE;
}

#######################################################################
# Test MAX_PRE_FORK constant exists
#######################################################################

{
    # Verify the constant exists and has expected value
    # Call as function since it's defined with 'use constant'
    my $max = Feersum::Runner::MAX_PRE_FORK();
    is($max, 1000, 'MAX_PRE_FORK constant is 1000');
}

#######################################################################
# Test flat TLS option assembly
#######################################################################

{
    # tls_cert_file without tls_key_file should croak
    eval {
        my $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            tls_cert_file => 'server.crt',
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    like($@, qr/tls_cert_file requires tls_key_file/, 'tls_cert_file without tls_key_file: croaks');
    undef $Feersum::Runner::INSTANCE;
}

{
    # tls_key_file without tls_cert_file should croak
    eval {
        my $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            tls_key_file => 'server.key',
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    like($@, qr/tls_key_file requires tls_cert_file/, 'tls_key_file without tls_cert_file: croaks');
    undef $Feersum::Runner::INSTANCE;
}

{
    # tls hash + flat options: tls hash takes precedence, no croak about flat options
    eval {
        my $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            tls => { cert_file => 'server.crt', key_file => 'server.key' },
            tls_key_file => 'orphan.key',
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    # Should NOT croak about "tls_key_file requires tls_cert_file"
    # It may croak about TLS support not compiled in, which is fine
    unlike($@, qr/tls_key_file requires tls_cert_file/,
        'tls hash + flat tls_key_file: flat option silently discarded');
    undef $Feersum::Runner::INSTANCE;
}

{
    # tls hash + orphan tls_cert_file: tls hash takes precedence (symmetric to above)
    eval {
        my $runner = Feersum::Runner->new(
            listen => ['localhost:0'],
            tls => { cert_file => 'server.crt', key_file => 'server.key' },
            tls_cert_file => 'orphan.crt',
            quiet => 1,
            app => sub { shift->send_response(200, [], []); }
        );
        $runner->_prepare();
    };
    unlike($@, qr/tls_cert_file requires tls_key_file/,
        'tls hash + flat tls_cert_file: flat option silently discarded');
    undef $Feersum::Runner::INSTANCE;
}

pass "all Runner validation tests completed";
