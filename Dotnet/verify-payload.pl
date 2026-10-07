#!/usr/bin/perl

use strict;
use warnings;
use Digest::MD5;
use Fcntl qw(O_RDONLY O_NOFOLLOW O_NONBLOCK S_ISDIR S_ISREG);

# The installed package database and native tools are part of the trusted base.
# These digests check installed bytes, not package authenticity or application health.
my $install_root = '/';
my $trusted_uid = 0;
my $admindir = "$install_root/var/lib/dpkg";
$admindir =~ s{^//}{/};
my $limit = 1024 * 1024;

sub fail { die "debian13s4 runtime integrity: $_[0]\n"; }

sub path {
    my ($name) = @_;
    $name =~ m{\A/[A-Za-z0-9_+./-]+\z} &&
        $name !~ m{(?:\A|/)[.][.]?(?:/|\z)|//|/\z} or fail('invalid package path');
    return $install_root eq '/' ? $name : "$install_root$name";
}

sub trusted {
    my ($name, $kind) = @_;
    my $current = $name;
    while (1) {
        my @st = lstat($current);
        @st && $st[4] == $trusted_uid && !($st[2] & 0022) or fail("untrusted path: $current");
        ($current eq $name && $kind eq 'file' ? S_ISREG($st[2]) : S_ISDIR($st[2]))
            or fail("wrong path kind: $current");
        last if $current eq $install_root;
        $current =~ s{/[^/]+\z}{};
        $current = '/' if $current eq '';
    }
}

sub query {
    open(my $child, '-|', 'dpkg-query', "--admindir=$admindir", @_) or fail('query start failed');
    my $output = '';
    while (1) {
        my $count = read($child, my $buffer, 65536);
        defined $count or fail('query read failed');
        last if $count == 0;
        $output .= $buffer;
        length($output) <= $limit or fail('package metadata exceeds bound');
    }
    close($child) or fail('query failed');
    return $output;
}

sub digest {
    my ($name, $expected) = @_;
    trusted($name, 'file');
    my @before = lstat($name);
    sysopen(my $file, $name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or fail("cannot open: $name");
    binmode($file) or fail('binary mode failed');
    my @opened = stat($file);
    @opened && S_ISREG($opened[2]) && $opened[0] == $before[0] && $opened[1] == $before[1]
        or fail('payload identity changed');
    my $actual = Digest::MD5->new->addfile($file)->hexdigest;
    my @after = stat($file);
    my @named = lstat($name);
    @after && @named && S_ISREG($named[2]) &&
        join(':', @opened[0,1,2,4,7,9,10]) eq join(':', @after[0,1,2,4,7,9,10]) &&
        join(':', @after[0,1,2,4,7,9,10]) eq join(':', @named[0,1,2,4,7,9,10])
        or fail('payload changed during verification');
    close($file) or fail('payload close failed');
    $actual eq $expected or fail("checksum mismatch: $name");
}

trusted($admindir, 'directory');
trusted("$admindir/info", 'directory');
trusted("$admindir/status", 'file');
for my $package (qw(aspnetcore-runtime-10.0 dotnet-runtime-10.0 dotnet-runtime-deps-10.0
                   dotnet-hostfxr-10.0 dotnet-host)) {
    my $identity = query('--show', '--showformat=${binary:Package}\t${Status}\t${Version}\n', '--', $package);
    $identity =~ /\A(\Q$package\E(?::(?:amd64|arm64))?)\tinstall ok installed\t(10[.]0[.][0-9]+)-[0-9A-Za-z.+~]+\n\z/
        or fail("unusable package identity: $package");
    my ($binary, $version) = ($1, $2);
    # Validate the metadata leaves before the native queries can open them.
    # --control-path is needed for trust checks, not for reading the contents:
    # binary:Package can qualify a foreign architecture even without Multi-Arch.
    my $metadata = query('--control-path', $binary, 'md5sums');
    $metadata =~ m{\A(\Q$admindir/info/$package\E(?::(?:amd64|arm64))?)[.]md5sums\n\z}
        or fail('invalid checksum metadata location');
    my $metadata_base = $1;
    trusted("$metadata_base.md5sums", 'file');
    trusted("$metadata_base.list", 'file');
    my $manifest = query('--control-show', $binary, 'md5sums');
    my $inventory = query('--listfiles', '--', $binary);
    length($manifest) && length($inventory) && $manifest =~ /\n\z/ && $inventory =~ /\n\z/
        or fail('missing package metadata');
    my (%sums, %listed, %directories);
    # The dependency-only package also owns the shared installation directory.
    $directories{'/usr/share/dotnet'} = 1;
    for my $line (split(/\n/, $manifest)) {
        $line =~ m{\A([0-9a-f]{32})  ([A-Za-z0-9_+./-]+)\z} or fail('invalid checksum metadata');
        my ($hash, $relative) = ($1, $2);
        my $name = "/$relative";
        path($name);
        exists($sums{$name}) and fail('duplicate checksum metadata');
        $sums{$name} = $hash;
        if ($name =~ m{\A/usr/share/dotnet/}) {
            my $parent = $name;
            while ($parent =~ s{/[^/]+\z}{}) { $directories{$parent} = 1; }
        }
    }
    for my $name (split(/\n/, $inventory)) {
        next if $name eq '/.' || $name eq '/';
        path($name);
        exists($listed{$name}) and fail('duplicate package inventory');
        $listed{$name} = 1;
        next unless $name =~ m{\A/usr/share/dotnet(?:/|\z)};
        if (exists($sums{$name})) {
            digest(path($name), $sums{$name});
        } else {
            $directories{$name} or fail("no checksum coverage: $name");
            trusted(path($name), 'directory');
        }
    }
    for my $name (keys %sums) {
        next unless $name =~ m{\A/usr/share/dotnet/};
        $listed{$name} or fail("checksum absent from inventory: $name");
    }
    my @required;
    if ($package eq 'dotnet-host') {
        @required = ('/usr/share/dotnet/dotnet');
    } elsif ($package eq 'dotnet-hostfxr-10.0') {
        @required = ("/usr/share/dotnet/host/fxr/$version/libhostfxr.so");
    } elsif ($package eq 'dotnet-runtime-10.0') {
        @required = map { "/usr/share/dotnet/shared/Microsoft.NETCore.App/$version/$_" }
            qw(libcoreclr.so libclrjit.so libhostpolicy.so libSystem.Native.so
               libSystem.Globalization.Native.so libSystem.IO.Compression.Native.so
               libSystem.Net.Security.Native.so libSystem.Security.Cryptography.Native.OpenSsl.so
               System.Private.CoreLib.dll System.Runtime.dll Microsoft.NETCore.App.deps.json
               Microsoft.NETCore.App.runtimeconfig.json);
    } elsif ($package eq 'aspnetcore-runtime-10.0') {
        @required = map { "/usr/share/dotnet/shared/Microsoft.AspNetCore.App/$version/$_" }
            qw(Microsoft.AspNetCore.dll Microsoft.AspNetCore.Hosting.dll Microsoft.AspNetCore.Http.dll
               Microsoft.AspNetCore.Server.Kestrel.dll Microsoft.AspNetCore.App.deps.json
               Microsoft.AspNetCore.App.runtimeconfig.json);
    }
    for my $name (@required) {
        exists($sums{$name}) && $listed{$name} or fail("required payload is not verifiable: $name");
    }
}
