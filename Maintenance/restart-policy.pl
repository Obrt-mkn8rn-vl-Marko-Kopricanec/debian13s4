#!/usr/bin/perl
use strict;
use warnings;

# Apply the same sorted, first-match service exclusions as Debian needrestart.
# Batch output precedes native override_rc/refusal handling, so it is only input
# to this selector; it is never permission to restart every reported service.
our %nrconf = (defno => 0, verbosity => 0, blacklist_rc => [], override_rc => {},
              restart_d => '/etc/needrestart/restart.d');
@ARGV == 1 || @ARGV == 2 or die "Expected the trusted needrestart configuration and optional original name.\n";
my $loaded = do $ARGV[0];
die "Cannot load restart policy: $@ $!\n" if $@ || (!defined($loaded) && $!);
sub validate_name {
    my ($name) = @_;
    $name =~ /\A[A-Za-z0-9_.@][A-Za-z0-9_.@:\\-]*\z/ && length($name) <= 255 &&
        $name ne '@reboot' && $name !~ /\A\@reboot:/
        or die "Invalid restart target.\n";
    my $unit = $name =~ /\.service\z/ ? $name : "$name.service";
    length($unit) <= 255 or die "Restart unit name is too long.\n";
    return $name;
}
if (@ARGV == 2) {
    my $name = validate_name($ARGV[1]);
    my $hook = "$nrconf{restart_d}/$name";
    print "$hook\n" or die "Cannot write hook path: $!\n" if -x $hook;
    exit 0;
}
my %seen;
while (my $line = <STDIN>) {
    next unless $line =~ /^NEEDRESTART-SVC: (.*)\n$/;
    my $name = validate_name($1);
    next if grep { $name =~ /$_/ } @{$nrconf{blacklist_rc}};
    my $allowed = !$nrconf{defno};
    for my $pattern (sort keys %{$nrconf{override_rc}}) {
        next unless $name =~ /$pattern/;
        $allowed = $nrconf{override_rc}->{$pattern};
        last;
    }
    next unless $allowed;
    # These pseudo-targets describe init managers, not individual services.
    # A controlled reboot activates their replacement without running the
    # unchecked multi-process init-manager hooks.
    my $target = $name;
    if ($name =~ /\A(?:systemd-manager|systemd-user|sysv-init)\z/) {
        $target = '@reboot';
    }
    # Journal the original policy/hook identity. The controller derives the
    # systemd observation name without changing what future policy checks see.
    print "$target\n" or die "Cannot write restart plan: $!\n" unless $seen{$target}++;
}
