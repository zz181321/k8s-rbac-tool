# Purpose of Creation

Kubernetes relies on external systems for user management and authentication, making it challenging to view Kubernetes users and their permissions at a glance in a CLI environment. The purpose of this tool is to make it convenient to query and explore Kubernetes in a CLI environment.


# Why GO Language?

The GO language was chosen for the following reasons:

- Specialized for CLI environments, allowing implementation without external library dependencies.
- Code readability.
- Kubernetes is written in GO.
- Compiles all libraries statically, creating a binary.
- Executable without compilation, like script languages.


# Required Packages

golang-bin


# Execution

To run the tool, you can use the following commands:

sudo go run rbac-tool.go <options>

or

sudo go build rbac-tool.go
./rbac-tool <options>


# Option Descriptions

There are two main options: "show" and "get."

- "show" directly outputs data received from the Kubernetes API server in tabular format, primarily for verification and debugging purposes. It retrieves and outputs role, cluster role, role binding, and cluster role binding from the Kubernetes API server.

- "get" processes data received from the Kubernetes API server, combines it into a new format, and outputs it in a tabular form. It includes user permission queries and the ability to save the data in CSV format.


# Available Options

- "show table role [--nosys]"
- "show table rolebinding [--nosys]"
- "show table clusterrole [--nosys]"
- "show table clusterrolebinding [--nosys] [--extended | -ext]"
- "show core"
- "show verbs"
- "get user [--more] [--overpowered | -op]"
- "get csv [user | role | rolebinding | clusterrole | clusterrolebinding]"


# How to Use

1.1 "show table <TYPE>":

   - "table role": Outputs all roles in the cluster.
   - "table clusterrole": Outputs all cluster roles in the cluster.
   - "table rolebinding": Outputs all role bindings in the cluster.
   - "table clusterrolebinding": Outputs all cluster role bindings in the cluster.

1.2 Additional options that can be used with the above options:

   - "--nosys": Excludes system-related roles from the output.
   - "--extended" or "-ext": Can be used with the "clusterrolebinding" option to display additional attributes created by KubeSphere.

1.3 Usage examples:

sudo go run rbac-tool.go show table clusterrolebinding --nosys --extended


2.1 "get user":

   - "user": Outputs a list of all users in the cluster.

2.2 Additional options that can be used with the "get user" option:

   - "--more": Outputs a list of all users in the cluster along with their permissions, apiGroups, Resources, and Verbs.
   - "--overpowered" or "-op": Lists users suspected of having excessive permissions (implementation pending).

2.3 Usage example:

sudo go run rbac-tool.go get user --more


3.1 "get csv":

   - Saves the output in CSV format instead of displaying it on the screen.


3.2 Usage example:

sudo go run rbac-tool.go get csv user --more
