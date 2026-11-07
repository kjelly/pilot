package identityreconcile

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// How a planned operation becomes a FreeIPA command. Every option name and value
// form here is one the P2-4 captures show the server takes (internal/freeiparpc/
// testdata, spec §9): the API's own names (givenname, sn, displayname, mail,
// loginshell, homedirectory), not the CLI's or the roster's, which it refuses with
// OptionError. TestEveryOperationKindHasACommand ties the kinds to the stages.

// commandFor is the command of op. The password of a password operation is the
// only value it does not take from the plan: it is the caller's, taken at the
// last moment and put in the command only.
func commandFor(op Operation, password string) (freeiparpc.Command, error) {
	obj := []any{op.Object}
	switch op.Kind {
	case KindGroupCreate, KindMarkerCreate:
		opts, err := fieldOptions(op, false)
		if err != nil {
			return freeiparpc.Command{}, err
		}
		return freeiparpc.Command{Method: "group_add", Args: obj, Options: opts}, nil
	case KindGroupUpdate:
		opts, err := fieldOptions(op, true)
		if err != nil {
			return freeiparpc.Command{}, err
		}
		return freeiparpc.Command{Method: "group_mod", Args: obj, Options: opts}, nil
	case KindUserCreate:
		opts, err := fieldOptions(op, false)
		if err != nil {
			return freeiparpc.Command{}, err
		}
		return freeiparpc.Command{Method: "user_add", Args: obj, Options: opts}, nil
	case KindUserUpdate:
		opts, err := fieldOptions(op, true)
		if err != nil {
			return freeiparpc.Command{}, err
		}
		return freeiparpc.Command{Method: "user_mod", Args: obj, Options: opts}, nil
	case KindPasswordInitialize, KindPasswordReset:
		if password == "" {
			return freeiparpc.Command{}, fmt.Errorf("%s: no password to set", op.ID)
		}
		return freeiparpc.Command{Method: "passwd", Args: obj, Options: map[string]any{"password": password}}, nil
	case KindMemberUserRemove:
		return memberCommand("group_remove_member", op, "user"), nil
	case KindMemberGroupRemove:
		return memberCommand("group_remove_member", op, "group"), nil
	case KindMemberUserAdd:
		return memberCommand("group_add_member", op, "user"), nil
	case KindMemberGroupAdd:
		return memberCommand("group_add_member", op, "group"), nil
	case KindUserEnable:
		return freeiparpc.Command{Method: "user_enable", Args: obj}, nil
	case KindUserDisable:
		return freeiparpc.Command{Method: "user_disable", Args: obj}, nil
	case KindUserDelete:
		// Permanent, as the playbook's: no preserve (spec §7.9).
		return freeiparpc.Command{Method: "user_del", Args: obj}, nil
	case KindGroupDelete:
		return freeiparpc.Command{Method: "group_del", Args: obj}, nil
	}
	return freeiparpc.Command{}, fmt.Errorf("no command for the operation kind %q", op.Kind)
}

func memberCommand(method string, op Operation, memberType string) freeiparpc.Command {
	members := make([]any, 0, len(op.Members))
	for _, m := range op.Members {
		members = append(members, m)
	}
	return freeiparpc.Command{Method: method, Args: []any{op.Object}, Options: map[string]any{memberType: members}}
}

// fieldOptions turns an operation's fields into command options: the value each
// carries is what the plan decided it is to become. modify says the command is a
// mod, not an add, which matters for one value only: an empty mail is "" on add
// and an empty list on mod, the two forms the server was captured clearing or
// leaving out the attribute with (K21).
func fieldOptions(op Operation, modify bool) (map[string]any, error) {
	opts := map[string]any{}
	names := make([]string, 0, len(op.Fields))
	for k := range op.Fields {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		to := op.Fields[name].To
		switch name {
		case "mail":
			list, ok := to.([]string)
			if !ok {
				return nil, fmt.Errorf("%s: mail is %T, want a list of strings", op.ID, to)
			}
			switch {
			case len(list) == 0 && modify:
				opts[name] = []any{}
			case len(list) == 0:
				opts[name] = ""
			case len(list) == 1:
				opts[name] = list[0]
			default:
				values := make([]any, len(list))
				for i, v := range list {
					values[i] = v
				}
				opts[name] = values
			}
		case "uidnumber", "gidnumber":
			s, ok := to.(string)
			if !ok {
				return nil, fmt.Errorf("%s: %s is %T, want a decimal string", op.ID, name, to)
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s: %s %q is not a number", op.ID, name, s)
			}
			opts[name] = n
		case "nonposix":
			b, ok := to.(bool)
			if !ok {
				return nil, fmt.Errorf("%s: nonposix is %T, want a boolean", op.ID, to)
			}
			opts[name] = b
		case "description", "givenname", "sn", "displayname", "loginshell", "homedirectory":
			s, ok := to.(string)
			if !ok {
				return nil, fmt.Errorf("%s: %s is %T, want a string", op.ID, name, to)
			}
			opts[name] = s
		default:
			return nil, fmt.Errorf("%s: the field %q has no FreeIPA option", op.ID, name)
		}
	}
	return opts, nil
}
