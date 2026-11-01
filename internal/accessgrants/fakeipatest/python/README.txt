Test doubles for the FreeIPA Python client, used only by tests of
playbooks/check/files/freeipa-identity-object-observer.py. None of this ships.

ipalib/__init__.py   a fake `ipalib.api` that serves recorded user_find/group_find
                     replies from the JSON file named by PILOT_FAKE_IPA_SCENARIO
                     (written by the Go tests from internal/freeiparpc/testdata
                     captures, with the documented mutations) and refuses to
                     connect unless the Kerberos cache named by KRB5CCNAME holds
                     a ticket (the fake kinit in the tests writes one).
ipapython/ssh.py     a MODEL of FreeIPA 4.13.4 ipapython/ssh.py `SSHPublicKey`:
                     the same parse order and the same openssh() normal form,
                     written from the upstream source, not copied. It is a model,
                     and the real class is what runs on a FreeIPA host, so the
                     model is pinned to it: ../testdata/ssh-normalizer-4.13.4.json
                     holds 18 inputs run through the REAL
                     `ipapython.ssh.SSHPublicKey(k).openssh()` on a FreeIPA
                     4.13.4 server (2026-10-31, all inputs are throwaway public
                     keys), with the real output or the real rejection
                     (ValueError), and, for every accepted input, what FreeIPA
                     stored as ipasshpubkey after `user-mod --sshpubkey`.
                     playbooks/check/files/test_identity_object_observer.py
                     (KeyNormalizerModelTests) requires this model to give the
                     same output, and to refuse the same inputs, as the capture.

Every reply the fake ipalib serves is a capture of FreeIPA 4.13.4 (a JSON-RPC
reply's `result`, which is the dict ipalib's Command returns); none is
constructed:

  user_find, group_find        the 2026-10-27 sessions, internal/freeiparpc/testdata
                               (user-find-states, group-find-states, ...).
  config_show                  internal/freeiparpc/testdata/config-show: taken on
                               a live vm-target on 2026-10-31. FreeIPA reads
                               config["ipadefaultemaildomain"][0]; the real reply
                               has it as a one-element list, with value and
                               summary null, and 23 other attributes.
  preserved-users search       user_find(preserved=True, pkey_only=True): no
                               preserved user is user-find-no-match (byte-identical
                               to the live capture of that search); one is
                               user-find-preserved-one (a real `--preserve`d user,
                               DN under cn=deleted users,cn=accounts,cn=provisioning,
                               summary "1 user matched"). fakeipatest.PreservedUsers
                               substitutes the login into that entry for the logins
                               a test needs.

One container type differs from the captures: an in-process ipalib Command
returns tuples of str where JSON has lists, and an int count. The observer
accepts both (it checks for list or tuple, and for an int count); a live
in-process ipalib client on the same server returned exactly that shape for
config_show and the preserved-users search (2026-10-31).
