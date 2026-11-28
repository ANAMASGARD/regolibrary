# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	result = invalid_flag(obj.spec.containers[0])
	msg := {
		"alertMessage": "anonymous requests is enabled",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_api_server(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

invalid_flag(container) := result if {
	flags := get_flags(container)
	# A standalone "--" ends pflag parsing. Index zero is the executable.
	end := min({count(flags)} | {i |
		some i, arg in flags
		arg == "--"
	})
	arguments := [argument_tokens(arg) | some arg in array.slice(flags, 0, end)]

	# Preserve the legacy packed-argument fixture. Order matches first by
	# argument index and then by token index within that argument.
	[i, j] := max({[arg_index, token_index] |
		some arg_index, tokens in arguments
		arg_index > 0
		some token_index, token in tokens
		split(token, "=")[0] == "--service-account-lookup"
	})
	tokens := arguments[i]
	parts := split(tokens[j], "=")
	count(parts) == 2
	# These are the false spellings accepted by strconv.ParseBool.
	parts[1] in {"0", "f", "F", "false", "False", "FALSE"}

	path := flag_path(container, i)
	result := {
		"failed_paths": [path],
		"fix_paths": packed_fix(tokens, j, path),
	}
}

# Only split arguments that look like multiple whitespace-separated long flags.
argument_tokens(arg) := regex.find_n(`\s+|\S+`, arg, -1) if {
	regex.match(`^--[^\s]+(\s+--[^\s]+)+$`, arg)
} else := [arg]

packed_fix(tokens, index, path) := [{"path": path, "value": value}] if {
	count(tokens) > 1
	before := concat("", array.slice(tokens, 0, index))
	after := concat("", array.slice(tokens, index + 1, count(tokens)))
	value := concat("", [before, "--service-account-lookup=true", after])
} else := []

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args. The comprehension
# over args is null-safe (an explicit `args: null` yields [] rather than erroring).
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Map an index into the combined command+args list back to the real path, so
# findings on RKE2/k3s point at args[j] instead of a non-existent command[i].
flag_path(container, i) := sprintf("spec.containers[0].command[%d]", [i]) if {
	i < count(container.command)
} else := sprintf("spec.containers[0].args[%d]", [i - count(container.command)])
