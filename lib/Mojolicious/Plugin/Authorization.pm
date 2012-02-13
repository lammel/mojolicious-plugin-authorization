package Mojolicious::Plugin::Authorization;
use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app, $args) = @_;

    $args ||= {};

    die __PACKAGE__, ": missing 'check_user_role' subroutine ref in parameters\n"
        unless $args->{check_user_role} && ref($args->{check_user_role}) eq 'CODE';
    die __PACKAGE__, ": missing 'check_user_action' subroutine ref in parameters\n"
        unless $args->{check_user_action} && ref($args->{check_user_action}) eq 'CODE';

    my $check_auth_sub = sub {
        my ($c, $type, $all, $any) = @_;
        return unless $type eq "role" || $type eq "action";
        my $authall = 1;
        foreach (@$all) {
            $args->{"check_user_$type"}->($c, $_) || $authall = 0;
        }
        return unless $authall;
        $authany = 0;
        foreach (@$any) {
            $args->{"check_user_$type"}->($c, $_) && $authany = 1;
        }
        return unless $authany;
        return 1;
    }

#    $app->routes->add_condition(require_role => sub {
#        my ($r, $c, $captures, $required) = @_;
#        return ($required && $c->user_exists) ? 1 : 0;
#    });

    $app->helper(assert_role => sub {
        my ($c, $role) = @_;
        return ($check_auth_sub->($c, 'role', [$role])) ? 1 : 0;
    });

    $app->helper(assert_roles => sub {
        my ($c, $all, $any) = @_;
        return ($check_auth_sub->($c, 'role', $all, $any)) ? 1 : 0;
    });

    $app->helper(authorize => sub {
        my ($c, $type, $all, $any) = @_;
        return $check_auth_sub->($c, $type, $all, $any);
    });
}

1;
__END__
=head1 NAME

Mojolicious::Plugin::Authorization - A plugin to make authorization a bit easier

=head1 SYNOPSIS

    use Mojolicious::Plugin::Authorization

    $self->plugin('authorization' => {
        'check_user_role' => sub { ... },
        'check_user_action' => sub { ... },
    });

    if ($self->authorize('role', ['admin','staff'])) {
        ... 
    }


=head1 METHODS

=head2 authorize($type, $req_all, $req_any)

Authorize role or action (defined by $type). Items listed in arrayref $req_all 
will require all to be allowed for user. For items listed in $req_any array it 
will suffice if any of those is available.
.

=head2 allow_role($role)

Returns true if an authenticated user exists and has permissions for role.

=head2 allow_roles($req_all, $req_any)

Returns true if an authenticated user exists and has permissions for all roles 
provided in $req_any, or any role provided in $req_any.

=head1 CONFIGURATION

The following options can be set for the plugin:

=over 4

=item check_user_role (REQUIRED) A coderef for checking a user's role

=item check_user_action (REQUIRED) A coderef for checking if a user has permissions for action in any of his roles.

=back 

=head1 EXAMPLES

For a code example using this, see the F<t/01-functional.t> and F<t/02-functional_lazy.t> tests, it uses L<Mojolicious::Lite> and this plugin.

=head1 ROUTING VIA CONDITION

This plugin also exports a routing condition you can use in order to limit access to certain documents to only authenticated users.

    $r->route('/foo')->over(authorized_roles => [qw(admin staff)])->to('mycontroller#foo');

If someone is not authorized, these routes will not be considered by the dispatcher and unless you have set up a catch-all route, a 404 Not Found will be generated instead. 

=head1 ROUTING VIA CALLBACK

If you want to be able to send people to a login page, you will have to use the following:

    my $members_only = $r->route('/members')->to(cb => sub {
        my $self = shift;

        $self->redirect_to('/login') and return 0 unless($self->assert_role('admin'));
        return 1;
    });

=head1 SEE ALSO

L<Mojolicious::Sessions>, L<Mojolicious::Authentication>

=head1 AUTHOR

Roland Lammel, C<< <lammel at cpan.org> >>

=head1 BUGS / CONTRIBUTING

Please report any bugs or feature requests through the web interface at L<https://github.com/lammel/mojolicious-plugin-authorization/issues>.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mojolicious::Plugin::Authorization


You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Mojolicious-Plugin-Authorization>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Mojolicious-Plugin-Authorization>

=item * Search CPAN

L<http://search.cpan.org/dist/Mojolicious-Plugin-Authorization/>

=back

=head1 ACKNOWLEDGEMENTS

Ben van Staveren   
    -   For creating Mojolicous::Plugin::Authentication which inspired the work
        on this module

=head1 LICENSE AND COPYRIGHT

Copyright 2011-2012 Roland Lammel.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut
