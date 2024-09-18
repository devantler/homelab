# Infrastructure

> [!WARNING]
> Variables cannot be added in places where it would break the kustomize build.

These are flux post build variables, which allow limited templating of the manifests.

- `${variable_name}` - The syntax for a flux post build variable.
- `${variable_name:=default_value}` - The syntax for a flux post build variable with a default value.

To set the value of a variable, the value must be added to either the `variables.yaml` file or the `variables-sensitive.sops.yaml` file depending on the sensitivity of the value.

These files are available in this folder for global variables, in the clusters folder for cluster specific variables, and in the distributions folder for distribution specific variables.

> [!NOTE]
> To set a sensitive variable, you need `sops` to decrypt and encrypt the file. Alternatively, you can use `ksail` which embeds the `sops` binary, and provides a more user-friendly interface.


