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
                     written from the upstream source, not copied. It is a model:
                     the real class is what runs on a FreeIPA host, and the
                     observer's key identity relies on it. The vm-target
                     acceptance run (perturb, drift, apply, drift again) is what
                     confirms the model on the real class.

Replies that are CONSTRUCTED rather than captured (to be replaced by live
captures): config_show (fakeipatest.ConfigShow: FreeIPA reads
config["ipadefaultemaildomain"][0], so the attribute is a one-element list) and
the preserved-users search (fakeipatest.PreservedUsers: pkey-only entries shaped
like the captured user-find-states-pkey reply, with the preserved-users container
DN taken from the FreeIPA source).
