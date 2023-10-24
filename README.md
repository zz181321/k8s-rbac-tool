Required Packages:

golang-bin

Execution:

go run rbac-tool.go <options>

Options:

There are currently two available functionalities:

[Validation Table]: This feature loads and outputs role, cluster role, role binding, and cluster role binding from the Kubernetes API server.

[User Lookup]: Based on role binding and cluster role binding information retrieved from the Kubernetes API server, this feature filters and displays subjects (accounts) in User format. It then sorts and displays the roles and cluster roles associated with these accounts.

Validation Table:

--table role: Outputs all roles present in the cluster.
--table clusterrole: Outputs all cluster roles present in the cluster.
--table rolebinding: Outputs all role bindings present in the cluster.
--table clusterrolebinding: Outputs all cluster role bindings present in the cluster.

Additional options available with the above options:
--nosys: Excludes system-related roles from the output by default.
--extended or -ext: Can be used in conjunction with the clusterrolebinding option and displays additional attributes created in KubeSphere.

[Example]:
sudo go run rbac-tool.go --table clusterrolebinding --nosys --extended

User Lookup:

--list user: Outputs a list of all users in the cluster.
--list user --more: Outputs a list of all users in the cluster along with the apiGroups, Resources, and Verbs they have permissions for.

Additional options available with the above options:
--overpowered or -op: Filters and outputs a list of users suspected to have excessive permissions (currently in development).

[Example]:
sudo go run rbac-tool.go --list user
