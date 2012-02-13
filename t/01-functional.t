#!/usr/bin/env perl
use strict;
use warnings;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;
plan tests => 38;

# testing code starts here
use Mojolicious::Lite;
use Test::Mojo;

my $setup = {
    users => {
        'foo' => {
            username => 'foo',
            password => 'bar',
            roles => [ 'admin' ],
        },
        'bar' => {
            username => 'bar',
            password => 'baz',
            roles => [ 'guest' ],
        }
    },
    roles => {
        'admin' => {
            actions => [ qw(view modify update delete) ],
        }
        'guest' => {
            actions => [ qw(view) ],
        }
    }
};

### Pre-cache user actions for all user roles
foreach my $user (keys %{$setup->{users}}) {
    foreach my $role (@{$setup->{users}->{$user}->{roles}}) {
        $setup->{users}->{$user}->{role}->{$role} = 1;
        foreach my $action (@{$setup->{roles}->{$role}->{actions}}) {
            $setup->{users}->{$user}->{action}->{$action} = 1;
        }
    }
}

plugin 'authentication', {
    load_user => sub {
        my ($self, $uid) = @_;
        return {
            'username' => 'foo',
            'password' => 'bar',
            'name'     => 'Foo'
            } if($uid eq 'userid' || $uid eq 'useridwithextradata');
        return undef;
    },
    validate_user => sub {
        my ($self, $u, $p, $data) = @_;
        $u ||= ''; $p ||= ''; $data ||= {};

        return 'useridwithextradata' if($u eq 'foo' && $p eq 'bar' && ( $data->{'ohnoes'} || '' ) eq 'itsameme');
        return 'userid' if($u eq 'foo' && $p eq 'bar');
        return undef;
    },
};

plugin 'authorization', {
    check_user_role => sub {
        my ($self, $uid, $role) = @_;
        return ($setup->{$uid}->{role}->{$role});
    },
    check_user_action => sub {
        my ($self, $uid, $action) = @_;
        return ($setup->{$uid}->{action}->{$action});
    }
};


get '/' => sub {
    my $self = shift;
    $self->render(text => 'index page');
};

post '/login' => sub {
    my $self = shift;
    my $u    = $self->req->param('u');
    my $p    = $self->req->param('p');

    $self->render(text => ($self->authenticate($u, $p)) ? 'ok' : 'failed');
};

post '/auth' => sub {
    my $self = shift;
    my $u    = $self->req->param('u');
    my $p    = $self->req->param('p');

    $self->render(text => ($self->authenticate($u, $p, { 'ohnoes' => 'itsameme' })) ? 'ok' : 'failed');
};

get '/authonly' => sub {
    my $self = shift;
    $self->render(text => ($self->user_exists) ? 'authenticated' : 'not authenticated');
};

get '/condition/authonly' => (authenticated => 1) => sub {
    my $self = shift;
    $self->render(text => 'authenticated condition');
};

get '/logout' => sub {
    my $self = shift;

    $self->logout();
    $self->render(text => 'logout');
};

my $t = Test::Mojo->new;

$t->get_ok('/')->status_is(200)->content_is('index page');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');
$t->get_ok('/condition/authonly')->status_is(404);

# let's try this
$t->post_form_ok('/login', { u => 'fnark', p => 'fnork' })->status_is(200)->content_is('failed');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');

$t->post_form_ok('/login', { u => 'foo', p => 'bar' })->status_is(200)->content_is('ok');
$t->get_ok('/authonly')->status_is(200)->content_is('authenticated');
$t->get_ok('/condition/authonly')->status_is(200)->content_is('authenticated condition');

$t->get_ok('/logout')->status_is(200)->content_is('logout');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');

$t->post_form_ok('/login2', { u => 'foo', p => 'bar' })->status_is(200)->content_is('ok');
$t->get_ok('/authonly')->status_is(200)->content_is('authenticated');
$t->get_ok('/condition/authonly')->status_is(200)->content_is('authenticated condition');
