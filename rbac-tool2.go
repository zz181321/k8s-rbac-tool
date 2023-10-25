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
// for input flags
type InputFlags struct {
    TableType       string
    ListType        string
    ExcludeSystem   bool
    ExtendedOption  bool
    MoreOption      bool
    CoreOption      bool
    VerbsOption     bool
}

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
	OwnerReferences    []OwnerReference  `json:"ownerReferences,omitempty"`
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

// Structures for User list
type BindingDetail struct {
    BindingKind   string
    BindingName   string
    RoleRefKind   string
    RoleRefName   string
    RoleKind	  string
    Rules	  []RoleRule
}

type AccountInfo struct {
    AccountKind string
    AccountName string
    UserBindings    []BindingDetail
}



//var USERLIST []AccountInfo


// input options
func parseInputFlags() InputFlags {
    var flags InputFlags

    flag.StringVar(&flags.TableType, "table", "", "Display table types: 'clusterrole', 'role', 'clusterrolebinding', 'rolebinding'")
    flag.StringVar(&flags.ListType, "list", "", "Display list types: 'user'")
    flag.BoolVar(&flags.ExcludeSystem, "nosys", false, "Exclude default built-in system Roles")
    flag.BoolVar(&flags.ExtendedOption, "extended", false, "Display extended attributes (e.g. owner references)")
    flag.BoolVar(&flags.ExtendedOption, "ext", false, "Display extended attributes (e.g. owner references) [short form]")
    flag.BoolVar(&flags.MoreOption, "more", false, "Display User List with extended attributes")
    flag.BoolVar(&flags.CoreOption, "core", false, "Display built-in CORE API Resouces") 
    flag.BoolVar(&flags.VerbsOption, "verbs", false, "Display all available built-in verbs from api-resources") 

    flag.Parse()

    return flags
}

// initialize for sorting rules by APIGroup
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

            // 만약 resourceNames이 존재한다면 resource를 변경합니다.
            if len(rule.ResourceNames) > 0 {
                resource = fmt.Sprintf("%s.%s", resource, rule.ResourceNames[0]) // 여기서는 ResourceNames 중 첫 번째 것만을 사용.
            }

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
    fmt.Println("    --extended / -ext : show extra attributes (only work with Cluster Role Bindings.")

    // List user permissions section
    fmt.Println("\n[List User Permissions]")
    fmt.Println("  go run rbac-tool.go --list user --more [--overpowered | -op]")
    fmt.Println("    --more : Show user list table with more attributes.")
    fmt.Println("    --overpowered / -op: Highlight overpowered permissions.")

    // Verbs from api-resources section
    fmt.Println("\n[Available Verbs from API-Resources]")
    fmt.Println("  go run rbac-tool.go --verbs")
    
    // Display CORE API Resources section
    fmt.Println("\n[Built-in CORE API Resources]")
    fmt.Println("  go run rbac-tool.go --core")
    
    fmt.Println("===========================")
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

    readLines := bufio.NewScanner(bytes.NewReader(output))
    fmt.Println("# In Kubernetes, when the \"apiGroups\" entry is empty, it specifically refers to the following resources")
    fmt.Println("# (Built-in CORE API Resources)\n")
    for readLines.Scan() {
        line := readLines.Text()
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
func displayRoles(roles []Role, flags InputFlags, systemPrefixes []string) {

    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
    fmt.Fprintln(w, "Namespace\tKind\tRole Name\tapiGroups\tResources\tVerbs")
    fmt.Fprintln(w, "---------\t----\t---------\t---------\t---------\t-----")
    for _, role := range roles {
        if flags.ExcludeSystem && isSystemPrefix(role.Metadata.Name, systemPrefixes) {
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
func displayClusterRoles(roles []Role, flags InputFlags, systemPrefixes []string) {
    
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "Kind\tRole Name\tapiGroups\tResources\tVerbs")
	fmt.Fprintln(w, "----\t---------\t---------\t---------\t-----")

	for _, role := range roles {
		if flags.ExcludeSystem && isSystemPrefix(role.Metadata.Name, systemPrefixes) {
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



func displayClusterRoleBindings(bindings []ClusterRoleBinding, flags InputFlags, systemPrefixes []string) {
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)

    header := "Binding Name\tRole Kind\tLink to (Role Name)\tSubject Kind\tSubject Name\tAllows to (namespace)"
    if flags.ExtendedOption {
        header += "\tOwnerReferences (apiVersion, kind, name)"
    }
    fmt.Fprintln(w, header)

    separator := "------------\t---------\t-------\t------------\t------------\t---------"
    if flags.ExtendedOption {
        separator += "\t---------"
    }
    fmt.Fprintln(w, separator)

    for _, binding := range bindings {
        if flags.ExcludeSystem && isSystemPrefix(binding.Metadata.Name, systemPrefixes) {
            continue
        }

        if len(binding.Subjects) > 0 {
            namespace := "*"
            if binding.Subjects[0].Kind == "ServiceAccount" {
                namespace = binding.Subjects[0].Namespace
            }

            orStrings := []string{}
            for i, or := range binding.Metadata.OwnerReferences {
                if i == 0 {
                    orStrings = append(orStrings, fmt.Sprintf("%s,", or.APIVersion))
                    orStrings = append(orStrings, fmt.Sprintf("\t\t\t\t\t\t%s,", or.Kind))
                    orStrings = append(orStrings, fmt.Sprintf("\t\t\t\t\t\t%s", or.Name))
                } else {
                    orStrings = append(orStrings, fmt.Sprintf("%s,", or.APIVersion))
                    orStrings = append(orStrings, fmt.Sprintf("%s,", or.Kind))
                    orStrings = append(orStrings, fmt.Sprintf("%s", or.Name))
                }
            }

            if len(orStrings) == 0 {
                orStrings = append(orStrings, "-")
            }

            if flags.ExtendedOption {
                // Print first OwnerReference with other details
                fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", binding.Metadata.Name, binding.RoleRef.Kind, binding.RoleRef.Name, binding.Subjects[0].Kind, binding.Subjects[0].Name, namespace, orStrings[0])
                // Print remaining OwnerReferences
                for _, orString := range orStrings[1:] {
                    fmt.Fprintf(w, "%s\n", orString)
                }
            } else {
                // Just print without OwnerReferences
                fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", binding.Metadata.Name, binding.RoleRef.Kind, binding.RoleRef.Name, binding.Subjects[0].Kind, binding.Subjects[0].Name, namespace)
            }
            fmt.Fprintln(w, separator)
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

func displayRoleBindings(bindings []RoleBinding, flags InputFlags, systemPrefixes []string) {
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
    fmt.Fprintln(w, "Kind\tBinding Name\tAllows to (namespace)\tRole Kind\tLink to (Role Name)\tSubject Kind\tSubject Name\tSubject Namespace")
    fmt.Fprintln(w, "----\t------------\t---------\t---------\t-------\t------------\t------------\t-----------------")

    for _, binding := range bindings {
        if flags.ExcludeSystem && isSystemPrefix(binding.Metadata.Name, systemPrefixes) {
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
                fmt.Fprintln(w, "----\t------------\t---------\t---------\t-------\t------------\t------------\t-----------------")
            }
        }
    }
    w.Flush()
}


// processing user tables

func refineAccounts(refinedClusterBindings []ClusterRoleBinding, refinedRoleBindings []RoleBinding) ([]*AccountInfo, error) {
    
    var accounts []*AccountInfo

    // Process ClusterRoleBindings
    for _, clusterBinding := range refinedClusterBindings {
        for _, subject := range clusterBinding.Subjects {
            if subject.Kind == "User" {
                var account *AccountInfo
                accounts, account = findOrCreateAccount(accounts, subject.Kind, subject.Name)
                detail := BindingDetail{
                    BindingKind: clusterBinding.Kind,
                    BindingName: clusterBinding.Metadata.Name,
                    RoleRefKind: clusterBinding.RoleRef.Kind,
                    RoleRefName: clusterBinding.RoleRef.Name,
                }
                account.UserBindings = append(account.UserBindings, detail)
            }
        }
    }

    // Process RoleBindings
    for _, roleBinding := range refinedRoleBindings {
        for _, subject := range roleBinding.Subjects {
            if subject.Kind == "User" {
                var account *AccountInfo
                accounts, account = findOrCreateAccount(accounts, subject.Kind, subject.Name)
                detail := BindingDetail{
                    BindingKind: roleBinding.Kind,
                    BindingName: roleBinding.Metadata.Name,
                    RoleRefKind: roleBinding.RoleRef.Kind,
                    RoleRefName: roleBinding.RoleRef.Name,
                }
                account.UserBindings = append(account.UserBindings, detail)
            }
        }
    }

    // Sort based on AccountName
    sort.Slice(accounts, func(i, j int) bool {
        return accounts[i].AccountName < accounts[j].AccountName
    })

    return accounts, nil
}

// Helper function to find an existing account or create a new one
func findOrCreateAccount(accounts []*AccountInfo, kind, name string) ([]*AccountInfo, *AccountInfo) {
    for _, account := range accounts {
        if account.AccountName == name {
            return accounts, account
        }
    }

    // If not found, create a new account
    newAccount := &AccountInfo{
        AccountKind: kind,
        AccountName: name,
    }
    accounts = append(accounts, newAccount)
    return accounts, newAccount
}


func attachExtras(refinedAccounts []*AccountInfo, refinedRoles []Role, refinedClusterRoles []Role) []*AccountInfo {

for _, account := range refinedAccounts {
    for _, bindingDetail := range account.UserBindings {
        fmt.Println("Checking for bindingDetail:", bindingDetail.RoleRefName, "of kind:", bindingDetail.RoleRefKind)
        if bindingDetail.RoleRefKind == "ClusterRole" {
            for _, clusterRole := range refinedClusterRoles {
                fmt.Println("Matching with ClusterRole:", clusterRole.Metadata.Name)
                if clusterRole.Metadata.Name == bindingDetail.RoleRefName {
                    bindingDetail.Rules = clusterRole.Rules
                    bindingDetail.RoleKind = "ClusterRole"
                    fmt.Println("Assigned rules:", bindingDetail.Rules)
                    break
                }
            }
        } else if bindingDetail.RoleRefKind == "Role" {
            for _, role := range refinedRoles {
                fmt.Println("Matching with Role:", role.Metadata.Name)
                if role.Metadata.Name == bindingDetail.RoleRefName {
                    bindingDetail.Rules = role.Rules
                    bindingDetail.RoleKind = "Role"
                    fmt.Println("Assigned rules:", bindingDetail.Rules)
                    break
                }
            }
        }
    }
}
	return refinedAccounts
}


func displayUserTable(accounts []*AccountInfo, flags InputFlags) {
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)

    if flags.MoreOption {
        fmt.Fprintln(w, "Account Name\tKind\tRoleRefName\tRoleRefKind\tapiGroups\tResources\tVerbs")
        fmt.Fprintln(w, "------------\t----\t-----------\t-----------\t---------\t---------\t-----")
    } else {
        fmt.Fprintln(w, "Account Name\tKind\tRoleRefName\tRoleRefKind")
        fmt.Fprintln(w, "------------\t----\t-----------\t-----------")
    }

    prevAccountName := ""
    prevRoleRefName := ""

    for _, account := range accounts {
        displayAccountName := true

        for _, binding := range account.UserBindings {
            if flags.MoreOption && binding.RoleRefName != prevRoleRefName && prevRoleRefName != "" {
                if account.AccountName == prevAccountName {
                    fmt.Fprintln(w, "\t----\t-----------\t-----------\t---------\t---------\t-----")
                } else {
                    fmt.Fprintln(w, "------------\t----\t-----------\t-----------\t---------\t---------\t-----")
                }
            }

            if displayAccountName {
                fmt.Fprintf(w, "%s\t%s\t%s\t%s", account.AccountName, account.AccountKind, binding.RoleRefName, binding.RoleRefKind)
                displayAccountName = false
            } else {
                fmt.Fprintf(w, "\t%s\t%s\t%s", account.AccountKind, binding.RoleRefName, binding.RoleRefKind)
            }

            if flags.MoreOption && len(binding.Rules) > 0 {
	    fmt.Println("ExtraRules:", binding.Rules)
                rule := binding.Rules[0]
                fmt.Fprintf(w, "\t%s\t%s\t[%s]\n", strings.Join(rule.APIGroups, ","), strings.Join(rule.Resources, ","), strings.Join(rule.Verbs, ", "))

                for _, rule := range binding.Rules[1:] {
                    for _, apiGroup := range rule.APIGroups {
                        for _, resource := range rule.Resources {
                            fmt.Fprintf(w, "\t\t\t\t\t%s\t%s\t[%s]\n", apiGroup, resource, strings.Join(rule.Verbs, ", "))
                        }
                    }
                }
            } else {
                fmt.Fprintln(w)
            }

            prevRoleRefName = binding.RoleRefName
            prevAccountName = account.AccountName
        }

        if !flags.MoreOption {
            fmt.Fprintln(w, "------------\t----\t-----------\t-----------")
        }
    }
    w.Flush()
}



func main() {
//    systemPrefixes := []string{"system:", "kubeadm:", "calico","kubesphere","ks-","ingress-nginx","notification-manager","unity-","vxflexos"}
    systemPrefixes := []string{"system:", "kubeadm:", "kubesphere","ks-","ingress-nginx","notification-manager","unity-","vxflexos"}
    
    flags := parseInputFlags()

    if flags.VerbsOption {
        displayBuiltInVerbs()
        return
    }

    if flags.CoreOption {
	displayCoreResources()
	return
    }

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


    if flags.ListType == "user" {
        refinedAccounts, err := refineAccounts(refinedClusterBindings, refinedRoleBindings)
        if err != nil {
            fmt.Println("Error processing bindings:", err)
            return
        }
        if flags.MoreOption {
            refinedAccounts = attachExtras(refinedAccounts, refinedClusterRoles, refinedRoles)
        }
        displayUserTable(refinedAccounts, flags)
        return
    }

    switch flags.TableType {
    case "clusterrole":
        displayClusterRoles(refinedClusterRoles, flags, systemPrefixes)
    case "clusterrolebinding":
        displayClusterRoleBindings(refinedClusterBindings, flags, systemPrefixes)
    case "role":
        displayRoles(refinedRoles, flags, systemPrefixes)
    case "rolebinding":
        displayRoleBindings(refinedRoleBindings, flags, systemPrefixes)
    default:
        displayUsage()
    }
}
