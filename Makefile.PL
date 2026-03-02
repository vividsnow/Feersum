use 5.008007;
use ExtUtils::MakeMaker 6.51;
use EV::MakeMaker qw/ev_args/;

{
    package MY;
    sub test_via_harness {
      my($self, $perl, $tests) = @_;
      local $_ = $self->SUPER::test_via_harness($perl, $tests);
      s/PERL_DL_NONLAZY=1//g;
      return $_;
    }
    sub test_via_script {
      my($self, $perl, $tests) = @_;
      local $_ = $self->SUPER::test_via_script($perl, $tests);
      s/PERL_DL_NONLAZY=1//g;
      return $_;
    }
}

my $otherldflags = '';
my $convert_deps = 1;
my $force_no_tls = 0;
my $force_no_h2  = 0;

# Filter out our custom flags before MakeMaker sees them
@ARGV = grep {
    if    ($_ eq '-NOTLS') { $force_no_tls = 1; 0 }
    elsif ($_ eq '-NOH2')  { $force_no_h2  = 1; 0 }
    else                   { 1 }
} @ARGV;

if (defined $ARGV[0] && $ARGV[0] =~ /^-DEBUG=?(\d*)$/) {
    my $n = $1 || 1;
    my $opt = "OPTIMIZE=-DDEBUG=$n -g";
    # with 5.12.1 and the -DDEBUGGING flag:
    # dyld: Symbol not found: _Perl_pad_sv
    $opt .= ($] >= 5.012_001) ? '' : ' -DDEBUGGING';
    $ARGV[0] = $opt;
}
elsif (defined $ARGV[0] && $ARGV[0] eq '-PROFILE') {
    shift @ARGV;
    $ARGV[0] = "OPTIMIZE=-g -fprofile-arcs -ftest-coverage";
    $otherldflags = '-lgcov';
}
elsif (defined $ARGV[0] && $ARGV[0] eq '-PROFILEUSE') {
    $ARGV[0] = "OPTIMIZE=-g -O3 -fprofile-use";
    $otherldflags = '-fprofile-use';
}
elsif (defined $ARGV[0] && $ARGV[0] eq '-CPAN') {
    $convert_deps = 0;
}

# Convert optional Plack and other dependencies to a real dependency if it's
# present at build-time. (Fix:
# https://rt.cpan.org/Public/Bug/Display.html?id=65239)
my %want = (
    'Plack'           => 0.995,
    'JSON::XS'        => 2.0,
    'Test::LeakTrace' => 0.13,
    'Test::TCP'       => 1.12,
    'Test::SharedFork'=> 0.25,
);
my %have;

if ($convert_deps) {
    local $@;
    while (my ($pkg,$ver) = each %want) {
        $have{$pkg} = eval "require $pkg; \$$pkg\::VERSION >= $ver";
    }
}

# Set this to false if you get core-dumps. Gives a pretty good perf boost for
# simple responses. Look for FEERSUM_STEAL in the code to see what this does.
# In a nutshell: certain temporary values passed in as the body of a response
# have their string-value "stolen".  This very much doesn't work under threaded
# perl (5.8.7 and 5.12.1 were tested) and probably doesn't work prior to
# 5.12.0.
use Config;
my $steal = ($] >= 5.012 && !defined($Config{useithreads}));

# Optional TLS/H2 support
my (@extra_libs, @extra_defines, @extra_inc, @extra_objects);

# On older Linux (glibc < 2.17), clock_gettime lives in librt
if ($^O eq 'linux') {
    push @extra_libs, '-lrt';
}

# picotls for TLS 1.3 (vendored submodule in picotls-git/)
# Requires OpenSSL: detected via Alien::OpenSSL or system headers.
my $has_tls = 0;
if ($force_no_tls) {
    warn "Feersum: TLS support disabled (-NOTLS flag)\n";
} elsif (-d 'picotls-git/include' && -f 'picotls-git/lib/picotls.c') {
    # Try Alien::OpenSSL first, then fall back to system OpenSSL detection
    my ($openssl_cflags, $openssl_libs);
    if (eval { require Alien::OpenSSL; 1 }) {
        $openssl_cflags = Alien::OpenSSL->cflags;
        $openssl_libs   = Alien::OpenSSL->libs;
        warn "Feersum: OpenSSL found via Alien::OpenSSL\n";
    } else {
        # Fall back to probing system OpenSSL headers
        require ExtUtils::CBuilder;
        my $cb = ExtUtils::CBuilder->new(quiet => 1);
        my $test_src = "openssl_test_$$.c";
        {
            open my $fh, '>', $test_src or die "Cannot write $test_src: $!";
            # Check for OpenSSL >= 1.1.0 (X25519 support required by picotls)
            print $fh "#include <openssl/opensslv.h>\n";
            print $fh "#if OPENSSL_VERSION_NUMBER < 0x10100000L\n";
            print $fh "#error OpenSSL too old for picotls (need >= 1.1.0)\n";
            print $fh "#endif\n";
            print $fh "#include <openssl/evp.h>\n";
            print $fh "int main() { return 0; }\n";
            close $fh;
        }
        my $has_openssl = eval { $cb->compile(source => $test_src); 1 };
        unlink $test_src;
        unlink "openssl_test_$$.o";

        if ($has_openssl) {
            $openssl_cflags = '';
            $openssl_libs   = '-lssl -lcrypto';
            warn "Feersum: OpenSSL found via system headers\n";
        }
    }

    if ($openssl_cflags || $openssl_libs) {
        push @extra_inc,     '-Ipicotls-git/include';
        push @extra_inc,     $openssl_cflags if $openssl_cflags && $openssl_cflags =~ /\S/;
        push @extra_defines, '-DFEERSUM_HAS_TLS';
        push @extra_libs,    $openssl_libs;
        # Build picotls source files as object files
        push @extra_objects, 'picotls-core.o', 'picotls-openssl.o', 'picotls-pembase64.o', 'picotls-hpke.o';
        $has_tls = 1;
        warn "Feersum: TLS support enabled (picotls vendored submodule)\n";
    } else {
        warn "Feersum: TLS support disabled (OpenSSL not found; install Alien::OpenSSL or OpenSSL dev headers)\n";
    }
} else {
    warn "Feersum: TLS support disabled (picotls-git submodule not found)\n";
}

# Optional: nghttp2 for HTTP/2 (via Alien::nghttp2, requires TLS)
if ($force_no_h2) {
    warn "Feersum: HTTP/2 support disabled (-NOH2 flag)\n";
} elsif ($has_tls && eval { require Alien::nghttp2; 1 }) {
    my $cflags = Alien::nghttp2->cflags;
    my $libs   = Alien::nghttp2->libs;
    push @extra_inc,     $cflags if $cflags =~ /\S/;
    push @extra_libs,    $libs;
    push @extra_defines, '-DFEERSUM_HAS_H2';
    warn "Feersum: HTTP/2 support enabled (nghttp2 via Alien::nghttp2)\n";
} elsif ($has_tls) {
    warn "Feersum: HTTP/2 support disabled (Alien::nghttp2 not found)\n";
}

# Optional: USDT probes (requires sys/sdt.h and dtrace)
our $has_usdt = 0;
{
    require ExtUtils::CBuilder;
    my $cb = ExtUtils::CBuilder->new(quiet => 1);
    my $test_src = "sdt_test_$$.c";
    {
        open my $fh, '>', $test_src or die "Cannot write $test_src: $!";
        print $fh "#include <sys/sdt.h>\nint main() { return 0; }\n";
        close $fh;
    }
    $has_usdt = eval { $cb->compile(source => $test_src); 1 };
    unlink $test_src;
    unlink "sdt_test_$$.o";
    if ($has_usdt) {
        push @extra_defines, '-DFEERSUM_HAS_USDT';
        # macOS sys/sdt.h + dtrace -h macros are self-contained (no .o needed).
        # Linux (systemtap) and BSDs (real DTrace) need a probe object.
        if ($^O ne 'darwin') {
            push @extra_objects, 'feersum_probes.o';
        }
        warn "Feersum: USDT probes enabled (sys/sdt.h found)\n";
    } else {
        warn "Feersum: USDT probes disabled (sys/sdt.h not found)\n";
    }
}

WriteMakefile(ev_args(
    NAME          => 'Feersum',
    VERSION_FROM  => 'lib/Feersum.pm',
    ABSTRACT_FROM => 'lib/Feersum.pm',
    AUTHOR        => 'Jeremy Stashewsky <stash@cpan.org>',
    LICENSE       => 'perl',
    MIN_PERL_VERSION => '5.014',
    CONFIGURE_REQUIRES => {
        'EV' => 4.00,
        'EV::MakeMaker' => 0,
        'ExtUtils::CBuilder' => 0,
        'ExtUtils::MakeMaker' => 6.51,
    },
    BUILD_REQUIRES => {
        'AnyEvent' => 5.261,
        'Guard' => 1.012,
        'Test::More' => 0.94,
        'Test::Fatal' => 0.003,
        map { $_ => $want{$_} } grep { /^Test::/ && $have{$_} } keys %want
    },
    PREREQ_PM => {
        'EV' => 4.00,
        'Scalar::Util' => 1.19,
        map { $_ => $want{$_} } grep { !/^Test::/ && $have{$_} } keys %want
    },
    META_MERGE => {
        recommends => {
            'Alien::OpenSSL' => 0,
            'Alien::nghttp2' => 0,
            map { $_ => $want{$_} } grep { !$have{$_} } keys %want
        },
        resources => {
            repository => 'https://github.com/stash/Feersum.git',
            license => 'http://dev.perl.org/licenses/',
        },
        'no_index' => {directory => ['eg','picohttpparser-git','picotls-git']},
    },
    LIBS   => [join(' ', @extra_libs) || ''],
    EXE_FILES => ['bin/feersum'],
    DEFINE => join(' ', ($steal ? '-DFEERSUM_STEAL' : ''), @extra_defines),
    INC    => join(' ', '-I.', @extra_inc),
    dynamic_lib => {OTHERLDFLAGS => $otherldflags},
    (@extra_objects ? (OBJECT => '$(BASEEXT)$(OBJ_EXT) ' . join(' ', @extra_objects)) : ()),
));

# Custom build rules for picotls object files
package MY;
sub postamble {
    my $self = shift;
    my $postamble = '';
    if (-d 'picotls-git/include') {
        $postamble .= <<'MAKE';

picotls-core.o: picotls-git/lib/picotls.c picotls-git/include/picotls.h
	$(CC) -c $(PASTHRU_INC) $(INC) $(CCFLAGS) $(OPTIMIZE) $(CCCDLFLAGS) $(DEFINE) -Ipicotls-git/include -o picotls-core.o picotls-git/lib/picotls.c

picotls-openssl.o: picotls-git/lib/openssl.c picotls-git/include/picotls/openssl.h picotls-git/include/picotls.h
	$(CC) -c $(PASTHRU_INC) $(INC) $(CCFLAGS) $(OPTIMIZE) $(CCCDLFLAGS) $(DEFINE) -Ipicotls-git/include -o picotls-openssl.o picotls-git/lib/openssl.c

picotls-pembase64.o: picotls-git/lib/pembase64.c picotls-git/include/picotls.h picotls-git/include/picotls/pembase64.h
	$(CC) -c $(PASTHRU_INC) $(INC) $(CCFLAGS) $(OPTIMIZE) $(CCCDLFLAGS) $(DEFINE) -Ipicotls-git/include -o picotls-pembase64.o picotls-git/lib/pembase64.c

picotls-hpke.o: picotls-git/lib/hpke.c picotls-git/include/picotls.h
	$(CC) -c $(PASTHRU_INC) $(INC) $(CCFLAGS) $(OPTIMIZE) $(CCCDLFLAGS) $(DEFINE) -Ipicotls-git/include -o picotls-hpke.o picotls-git/lib/hpke.c

MAKE
    }

    if ($main::has_usdt) {
        $postamble .= <<'MAKE';

Feersum.o: feersum_probes.h

feersum_probes.h: feersum_probes.d
	dtrace -h -s feersum_probes.d -o feersum_probes.h

MAKE
        if ($^O eq 'linux') {
            # Systemtap dtrace -G creates a stub object
            $postamble .= <<'MAKE';
feersum_probes.o: feersum_probes.d
	dtrace -G -s feersum_probes.d -o feersum_probes.o

MAKE
        } elsif ($^O ne 'darwin') {
            # Real DTrace (NetBSD, FreeBSD, Solaris): needs compiled object
            $postamble .= <<'MAKE';
feersum_probes.o: feersum_probes.d Feersum.o
	dtrace -G -s feersum_probes.d Feersum.o -o feersum_probes.o

MAKE
        }
    }

    $postamble .= <<'MAKE';

clean ::
	$(RM_F) picotls-core.o picotls-openssl.o picotls-pembase64.o picotls-hpke.o feersum_probes.h feersum_probes.o

MAKE
    return $postamble;
}
