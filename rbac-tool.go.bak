package main
import (
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "text/tabwriter"
    "flag"
    "sort"
    "bufio"
    "bytes"
)
// structures for Roles (Typically, roles are associated with a NAMESPACE.)
type Role struct {
    APIVersion string       `json:"apiVersion"`
    Kind       string       `json:"kind"`
    Metadata   RoleMetadata `json:"metadata"`
    Rules      []RoleRule   `json:"rules"`
}
type RoleMetadata struct {
    Annotations        map[string]string `json:"annotations"`
    CreationTimestamp  string            `json:"creationTimestamp"`
    Labels             map[string]string `json:"labels"`
    Name               string            `json:"name"`
    Namespace          string            `json:"namespace"`
    ResourceVersion    string            `json:"resourceVersion"`
    UID                string            `json:"uid"`
}
type RoleRule struct {
    APIGroups     []string `json:"apiGroups"`
    ResourceNames []string `json:"resourceNames,omitempty"`
    Resources     []string `json:"resources"`
    Verbs         []string `json:"verbs"`
}
// Structures for ClusterRoles
type ClusterRole struct {
    APIVersion string              `json:"apiVersion"`
    Kind       string              `json:"kind"`
    Metadata   ClusterRoleMetadata `json:"metadata"`
    Rules      []ClusterRoleRule   `json:"rules"`
}
type ClusterRoleMetadata struct {
    Annotations        map[string]string `json:"annotations"`
    CreationTimestamp  string            `json:"creationTimestamp"`
    Labels             map[string]string `json:"labels"`
    Name               string            `json:"name"`
    ResourceVersion    string            `json:"resourceVersion"`
    UID                string            `json:"uid"`
}
type ClusterRoleRule struct {
    APIGroups     []string `json:"apiGroups"`
    ResourceNames []string `json:"resourceNames,omitempty"`
    Resources     []string `json:"resources"`
    Verbs         []string `json:"verbs"`
}

// Structures for Cluster Role Bindings
type ClusterRoleBinding struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   ClusterRoleBindingMeta `json:"metadata"`
	RoleRef    ClusterRoleRef         `json:"roleRef"`
	Subjects   []ClusterSubject       `json:"subjects"`
}

type ClusterRoleBindingMeta struct {
	Annotations        map[string]string `json:"annotations"`
	CreationTimestamp  string            `json:"creationTimestamp"`
	Name               string            `json:"name"`
	ResourceVersion    string            `json:"resourceVersion"`
	UID                string            `json:"uid"`
	OwnerReferences    []OwnerReference  `json: "ownerReferences,omitempty"`
}

type ClusterRoleRef struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

type ClusterSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}
// it's a custom field from KubeSphere
type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller,omitempty"`
	BlockOwnerDeletion *bool `json:"blockOwnerDeletion,omitempty"`
}


// Structures for Role Bindings
type RoleBinding struct {
    ApiVersion string   `json:"apiVersion"`
    Kind       string   `json:"kind"`
    Metadata   RoleBindingMeta `json:"metadata"`
    RoleRef    BindingRoleRef  `json:"roleRef"`
    Subjects   []BindingSubject `json:"subjects"`
}

type RoleBindingMeta struct {
    CreationTimestamp string            `json:"creationTimestamp"`
    Name              string            `json:"name"`
    Namespace         string            `json:"namespace,omitempty"`
    ResourceVersion   string            `json:"resourceVersion"`
    UID               string            `json:"uid"`
    Annotations       map[string]string `json:"annotations,omitempty"`
    Labels            map[string]string `json:"labels,omitempty"`
}

type BindingRoleRef struct {
    ApiGroup string `json:"apiGroup"`
    Kind     string `json:"kind"`
    Name     string `json:"name"`
}

type BindingSubject struct {
    ApiGroup  string `json:"apiGroup,omitempty"`
    Kind      string `json:"kind"`
    Name      string `json:"name"`
    Namespace string `json:"namespace,omitempty"`
}



// Structure for sorting rules by APIGroup
type SortByAPIGroup []RoleRule
func (a SortByAPIGroup) Len() int           { return len(a) }
func (a SortByAPIGroup) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortByAPIGroup) Less(i, j int) bool {
    if len(a[i].APIGroups) == 0 {
        return true
    }
    if len(a[j].APIGroups) == 0 {
        return false
    }
    return a[i].APIGroups[0] < a[j].APIGroups[0] 
}

// merge Verbs from rules.
func mergeRules(rules []RoleRule) []RoleRule {
    merged := make(map[string]map[string]map[string]struct{})
    allVerbs := map[string]struct{}{
        "get":              {},
        "list":             {},
        "watch":            {},
        "create":           {},
        "delete":           {},
        "deletecollection": {},
        "patch":            {},
        "update":           {},
    }
    for _, rule := range rules {
        for _, apiGroup := range rule.APIGroups {
            for _, resource := range rule.Resources {
                if _, ok := merged[apiGroup]; !ok {
                    merged[apiGroup] = make(map[string]map[string]struct{})
                }
                if _, ok := merged[apiGroup][resource]; !ok {
                    merged[apiGroup][resource] = make(map[string]struct{})
                }
                for _, verb := range rule.Verbs {
                    merged[apiGroup][resource][verb] = struct{}{}
                }
            }
        }
    }
    var mergedRules []RoleRule
    for apiGroup, resources := range merged {
        resourceVerbMap := make(map[string]map[string]struct{})
        for resource, verbs := range resources {
            if _, ok := resourceVerbMap[resource]; !ok {
                resourceVerbMap[resource] = make(map[string]struct{})
            }
            for verb := range verbs {
                resourceVerbMap[resource][verb] = struct{}{}
            }
        }
        // Sort the Resources in ascending order (오름차순)
        var sortedResources []string
        for resource := range resourceVerbMap {
            sortedResources = append(sortedResources, resource)
        }
        sort.Strings(sortedResources)
        for _, resource := range sortedResources {
            verbs := resourceVerbMap[resource]
            var verbList []string
            if len(verbs) == len(allVerbs) {
                verbList = []string{"*"}
            } else {
                for verb := range verbs {
                    verbList = append(verbList, verb)
                }
                sort.Strings(verbList)
            }
            mergedRules = append(mergedRules, RoleRule{
                APIGroups: []string{apiGroup},
                Resources: []string{resource},
                Verbs:     verbList,
            })
        }
    }
    return mergedRules
}


// Check if the role name has a default system prefix
func isSystemPrefix(itemName string, prefixes []string) bool {
    for _, prefix := range prefixes {
        if strings.HasPrefix(itemName, prefix) {
            return true
        }
    }
    return false
}

func displayUsage() {
    fmt.Println("===== RBAC Tool Usage =====")
    
    // Display tables section
    fmt.Println("\n[Display Tables for Validating RBAC Data]")
    fmt.Println("  go run rbac-tool.go --table <type> [--nosys]")
    fmt.Println("    <type>: role | rolebinding | clusterrole | clusterrolebinding")
    fmt.Println("    --nosys: Exclude system roles/bindings.")

    // List user permissions section
    fmt.Println("\n[List User Permissions]")
    fmt.Println("  go run rbac-tool.go --list user [--nosys] [--overpowered | -op]")
    fmt.Println("    --nosys: Exclude system roles/bindings.")
    fmt.Println("    --overpowered / -op: Highlight overpowered permissions.")

    // Verbs from api-resources section
    fmt.Println("\n[Available Verbs from API-Resources]")
    fmt.Println("  go run rbac-tool.go --verbs")
    
    // Display CORE API Resources section
    fmt.Println("\n[Built-in CORE API Resources]")
    fmt.Println("  go run rbac-tool.go --core")
    
    fmt.Println("===========================")
}

func parseInputFlags() (string, bool, bool, bool, bool) {
    var tableOption string
    var excludeSystem bool
    var verbsOption bool
    var coreOption bool
    var extendedOption bool
    flag.StringVar(&tableOption, "table", "", "Display roles in a table format (use 'clusterrole', 'role', etc.)")
    flag.BoolVar(&excludeSystem, "nosys", false, "Exclude default built-in system Roles")
    flag.BoolVar(&verbsOption, "verbs", false, "Display all available built-in verbs from api-resources")
    flag.BoolVar(&coreOption, "core", false, "Display built-in CORE API Resouces")
    flag.BoolVar(&extendedOption, "extended", false, "Display extended attributes (e.g. owner references)")
    flag.BoolVar(&extendedOption, "ext", false, "Display extended attributes (e.g. owner references) [short form]")
    flag.Parse()
    return tableOption, excludeSystem, verbsOption, coreOption, extendedOption
}

func displayBuiltInVerbs() {
    cmd := exec.Command("sh", "-c", "kubectl api-resources --no-headers --sort-by name -o wide | sed 's/.*\\[//g' | tr -d \"]\" | tr \" \" \"\\n\" | sort | uniq")
    output, err := cmd.Output()
    if err != nil {
        fmt.Println("Error executing the command:", err)
        return
    }
    fmt.Println("# Built-in Default Available Verbs")
    fmt.Println(string(output))
}

func displayCoreResources() {
    cmd := exec.Command("kubectl", "api-resources", "--api-group=", "--no-headers")
    output, err := cmd.Output()
    if err != nil {
        fmt.Println("Error executing kubectl api-resources command:", err)
        return
    }

    scanner := bufio.NewScanner(bytes.NewReader(output))
    fmt.Println("# Built-in CORE API Resources")
    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Fields(line) // Split the line by whitespace
        if len(fields) >= 5 {
            fmt.Println(fields[4])
        }
    }
    fmt.Println()
}

// The following 4 functions handle Kubernetes RBAC data and display for Roles & ClusterRoles:
// dataStoreRoles, dataStoreClusterRoles, displayRoles, displayClusterRoles

// store data for Roles
func dataStoreRoles() ([]Role, error) {
    cmd := exec.Command("kubectl", "get", "roles", "-A", "-o", "json")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    var rolesList struct {
        Items []Role `json:"items"`
    }

    err = json.Unmarshal(output, &rolesList)
    if err != nil {
        return nil, err
    }

    // apiGroups 정렬 및 Verbs 병합
    for i := range rolesList.Items {
        rolesList.Items[i].Rules = mergeRules(rolesList.Items[i].Rules)
        sort.Sort(SortByAPIGroup(rolesList.Items[i].Rules))
    }

    return rolesList.Items, nil
}

// store data for Cluster Roles
func dataStoreClusterRoles() ([]Role, error) {
    cmd := exec.Command("kubectl", "get", "clusterroles", "-o", "json")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    var rolesList struct {
        Items []Role `json:"items"`
    }

    err = json.Unmarshal(output, &rolesList)
    if err != nil {
        return nil, err
    }

    // apiGroups 정렬 및 Verbs 병합
    for i := range rolesList.Items {
        rolesList.Items[i].Rules = mergeRules(rolesList.Items[i].Rules)
        sort.Sort(SortByAPIGroup(rolesList.Items[i].Rules))
    }

    return rolesList.Items, nil
}


// function for drawing a table and displaying typical Roles
func displayRoles(roles []Role, excludeSystem bool, systemPrefixes []string) {

    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
    fmt.Fprintln(w, "Namespace\tKind\tRole Name\tapiGroups\tResources\tVerbs")
    fmt.Fprintln(w, "---------\t----\t---------\t---------\t---------\t-----")
    for _, role := range roles {
        if excludeSystem && isSystemPrefix(role.Metadata.Name, systemPrefixes) {
            continue
        }
        displayedHeader := false
        for _, rule := range role.Rules {
            for apiGroupIndex, apiGroup := range rule.APIGroups {
                for resourceIndex, resource := range rule.Resources {
                    if apiGroupIndex == 0 && !displayedHeader {
                        fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t [%s]\n", role.Metadata.Namespace, role.Kind, role.Metadata.Name, apiGroup, resource, strings.Join(rule.Verbs, ", "))
                        displayedHeader = true
                    } else if apiGroupIndex == 0 && resourceIndex == 0 { // 첫 번째 apiGroup이지만 resource는 첫 번째가 아닐 경우
                        fmt.Fprintf(w, "\t\t\t%s\t%s\t [%s]\n", apiGroup, resource, strings.Join(rule.Verbs, ", "))
                    } else { // 첫 번째 apiGroup이 아닐 경우
                        fmt.Fprintf(w, "\t\t\t%s\t%s\t\n", apiGroup, resource)
                    }
                }
            }
        }
        
        if displayedHeader {
            fmt.Fprintln(w, "---------\t----\t---------\t---------\t---------\t-----")
        }
    }
    w.Flush()    
}

// function for drawing a table and displaying Cluster Roles
func displayClusterRoles(roles []Role, excludeSystem bool, systemPrefixes []string) {
    
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "Kind\tRole Name\tapiGroups\tResources\tVerbs")
	fmt.Fprintln(w, "----\t---------\t---------\t---------\t-----")

	for _, role := range roles {
		if excludeSystem && isSystemPrefix(role.Metadata.Name, systemPrefixes) {
			continue
		}
		displayedHeader := false
		for _, rule := range role.Rules {
			for _, apiGroup := range rule.APIGroups {
				for _, resource := range rule.Resources {
					if !displayedHeader {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t [%s]\n", role.Kind, role.Metadata.Name, apiGroup, resource, strings.Join(rule.Verbs, ", "))
						displayedHeader = true
					} else {
						fmt.Fprintf(w, "\t\t%s\t%s\t [%s]\n", apiGroup, resource, strings.Join(rule.Verbs, ", "))
					}
				}
			}
		}
		if displayedHeader {
			fmt.Fprintln(w, "----\t---------\t----------\t---------\t-----")
		}
	}
	w.Flush()
}


// following functions handle Cluster Role Bindinds

func dataStoreClusterBindings() ([]ClusterRoleBinding, error) {
    // Run the kubectl command to get cluster role bindings
    cmd := exec.Command("kubectl", "get", "clusterrolebindings", "-o", "json")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    // Define a wrapper structure for the list of cluster role bindings
    var bindingsList struct {
        Items []ClusterRoleBinding `json:"items"`
    }

    // Unmarshal the JSON output into our wrapper structure
    err = json.Unmarshal(output, &bindingsList)
    if err != nil {
        return nil, err
    }

    return bindingsList.Items, nil
}


func displayClusterRoleBindings(bindings []ClusterRoleBinding, excludeSystem bool, systemPrefixes []string, extended bool) {
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
    
    header := "Binding Name\tRole Kind\tReference(Role Name)\tSubject Kind\tSubject Name\tAllows to (namespace)"
    if extended {
        header += "\tOwnerReferences (apiVersion, kind, name)"
    }
    fmt.Fprintln(w, header)

    separator := "------------\t---------\t---------\t------------\t------------\t---------"
    if extended {
        separator += "\t---------"
    }
    fmt.Fprintln(w, separator)

    for _, binding := range bindings {
        if excludeSystem && isSystemPrefix(binding.Metadata.Name, systemPrefixes) {
            continue
        }
        displayedHeader := false
        for index, subject := range binding.Subjects {
            namespace := subject.Namespace
            if namespace == "" {
                namespace = "*"
            }

            orString := ""
            if extended {
                orString = "-"
                for _, or := range binding.Metadata.OwnerReferences {
                    orString += fmt.Sprintf("(%s, %s, %s) ", or.APIVersion, or.Kind, or.Name)
                }
                if orString == "" {
                    orString = "-"
                }
            }

            if !displayedHeader {
                fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s", binding.Metadata.Name, binding.RoleRef.Kind, binding.RoleRef.Name, subject.Kind, subject.Name, namespace)
                if extended {
                    fmt.Fprintf(w, "\t%s", orString)
                }
                fmt.Fprintln(w)
                displayedHeader = true
            } else {
                fmt.Fprintf(w, "\t\t\t%s\t%s\t%s", subject.Kind, subject.Name, namespace)
                if extended {
                    fmt.Fprintf(w, "\t%s", orString)
                }
                fmt.Fprintln(w)
            }

            if index == len(binding.Subjects) - 1 {
                fmt.Fprintln(w, separator)
            }
        }
    }
    w.Flush()
}


// following functions handle Role Bindinds

func dataStoreRoleBindings() ([]RoleBinding, error) {
    // Run the kubectl command to get cluster role bindings
    cmd := exec.Command("kubectl", "get", "rolebindings", "-A", "-o", "json")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    // Define a wrapper structure for the list of cluster role bindings
    var bindingsList struct {
        Items []RoleBinding `json:"items"`
    }

    // Unmarshal the JSON output into our wrapper structure
    err = json.Unmarshal(output, &bindingsList)
    if err != nil {
        return nil, err
    }

    return bindingsList.Items, nil
}

func displayRoleBindings(bindings []RoleBinding, excludeSystem bool, systemPrefixes []string) {
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
    fmt.Fprintln(w, "Kind\tBinding Name\tAllows to (namespace)\tRole Kind\tReference(Role Name)\tSubject Kind\tSubject Name\tSubject Namespace")
    fmt.Fprintln(w, "----\t------------\t---------\t---------\t---------\t------------\t------------\t-----------------")

    for _, binding := range bindings {
        if excludeSystem && isSystemPrefix(binding.Metadata.Name, systemPrefixes) {
            continue
        }
        displayedHeader := false
        for index, subject := range binding.Subjects {
            namespace := subject.Namespace
            if namespace == "" {
                namespace = "-"
            }

            if !displayedHeader {
                fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", 
                    binding.Kind, binding.Metadata.Name, binding.Metadata.Namespace, binding.RoleRef.Kind, 
                    binding.RoleRef.Name, subject.Kind, subject.Name, namespace)
                displayedHeader = true
            } else {
                fmt.Fprintf(w, "\t\t\t\t\t%s\t%s\t%s\n", subject.Kind, subject.Name, namespace)  
            }

            // Only print the separator line after the last subject of a binding
            if index == len(binding.Subjects) - 1 {
                fmt.Fprintln(w, "----\t------------\t---------\t---------\t---------\t------------\t------------\t-----------------")
            }
        }
    }
    w.Flush()
}



func main() {
//    systemPrefixes := []string{"system:", "kubeadm:", "calico","kubesphere","ks-","ingress-nginx","notification-manager","unity-","vxflexos"}
    systemPrefixes := []string{"system:", "kubeadm:", "kubesphere","ks-","ingress-nginx","notification-manager","unity-","vxflexos"}
    tableOption, excludeSystem, verbsOption, coreOption, extended := parseInputFlags()
    
    if verbsOption {
        displayBuiltInVerbs()
        return
    }

    if coreOption {
	displayCoreResources()
	return
    }


    // You should call the functions and store their return values
    refinedClusterRoles, err := dataStoreClusterRoles()
    if err != nil {
        fmt.Println("Error getting Cluster Role data:", err)
        return
    }
    
    refinedRoles, err := dataStoreRoles()
    if err != nil {
        fmt.Println("Error getting Role data:", err)
        return
    }
    
    refinedClusterBindings, err := dataStoreClusterBindings()
    if err != nil {
        fmt.Println("Error getting Cluster Role Binding data:", err)
        return
    }
    
    refinedRoleBindings, err := dataStoreRoleBindings()
    if err != nil {
        fmt.Println("Error getting Role Binding data:", err)
        return
    }


    switch tableOption {
    case "clusterrole":
        displayClusterRoles(refinedClusterRoles, excludeSystem, systemPrefixes)
    case "clusterrolebinding":
        displayClusterRoleBindings(refinedClusterBindings, excludeSystem, systemPrefixes, extended)
    case "role":
        displayRoles(refinedRoles, excludeSystem, systemPrefixes)
    case "rolebinding":
        displayRoleBindings(refinedRoleBindings, excludeSystem, systemPrefixes)
    default:
        displayUsage()
    }
}

