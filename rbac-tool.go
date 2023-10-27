package main
import (
    "encoding/json"
    "encoding/csv"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "text/tabwriter"
    "flag"
    "sort"
    "bufio"
    "bytes"
    "log"
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
    CSVWrite	    bool
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
type BindingInfo struct {
    Kind        string `json:"kind"`
    Namespace   string `json:"namespace"`
    RoleRefName string `json:"roleRefName"`
    RoleRefKind string `json:"roleRefKind"`
    // 구조체의 재사용
    ExtraRules []RoleRule `json:"rules"`
}

type AccountInfo struct {
    Name     	  string       `json:"name"`
    Bindings	  []BindingInfo `json:"bindings"`
}

var USERLIST []AccountInfo



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

    // "get csv" 파싱 로직 추가
    for i, arg := range os.Args {
        if arg == "get" && i+1 < len(os.Args) && os.Args[i+1] == "csv" {
            flags.CSVWrite = true
        }
    }

    return flags
}

func displayUsage() {
    fmt.Println("===== RBAC Tool Usage =====")
    // Display tables section
    fmt.Println("\n[Display Tables for Validating RBAC Data]")
    fmt.Println("  go run rbac-tool.go --table <type> [--nosys]")
    fmt.Println("    <type>: role | rolebinding | clusterrole | clusterrolebinding")
    fmt.Println("    --nosys: Exclude system roles/bindings.")
    fmt.Println("    --extended / -ext : show extra attributes (only work with Cluster Role Bindings.)")

    // List user permissions section
    fmt.Println("\n[List User Permissions]")
    fmt.Println("  go run rbac-tool.go --list user --more [--overpowered | -op] [get csv]")
    fmt.Println("    --more : Show user list table with more attributes.")
    fmt.Println("    --overpowered / -op: Highlight overpowered permissions.")
    fmt.Println("    using [get csv] : write the user list into a CSV format file.")

    // Verbs from api-resources section
    fmt.Println("\n[Available Verbs from API-Resources]")
    fmt.Println("  go run rbac-tool.go --verbs")

    // Display CORE API Resources section
    fmt.Println("\n[Built-in CORE API Resources]")
    fmt.Println("  go run rbac-tool.go --core")
    fmt.Println("===========================")
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


// user list table create & sort, merge

func processBindings(clusterRoles []Role, roles []Role, clusterRoleBindings []ClusterRoleBinding, roleBindings []RoleBinding) ([]AccountInfo, error) {
    // 초기화: USERLIST
    USERLIST = []AccountInfo{}

    // ClusterRoleBinding 데이터 처리
    for _, clusterBinding := range clusterRoleBindings {
        for _, subject := range clusterBinding.Subjects {
//	    if subject.Kind == "User" && (!excludeSystem || !strings.HasPrefix(subject.Name, "system:")){
//	    if subject.Kind == "User" && !strings.HasPrefix(subject.Name, "system:"){
	    if subject.Kind == "User" {
                info := BindingInfo{
                    Kind:        clusterBinding.Kind,
                    RoleRefName: clusterBinding.RoleRef.Name,
                    RoleRefKind: clusterBinding.RoleRef.Kind,
                }
                addToTable(subject.Name, info)
            }
        }
    }

    // RoleBinding 데이터 처리
    for _, roleBinding := range roleBindings {
        for _, subject := range roleBinding.Subjects {
//	    if subject.Kind == "User" && (!excludeSystem || !strings.HasPrefix(subject.Name, "system:")){
//	    if subject.Kind == "User" && !strings.HasPrefix(subject.Name, "system:"){
	    if subject.Kind == "User" {
                info := BindingInfo{
                    Kind:        roleBinding.Kind,
                    Namespace:   roleBinding.Metadata.Namespace,
                    RoleRefName: roleBinding.RoleRef.Name,
                    RoleRefKind: roleBinding.RoleRef.Kind,
                }
                addToTable(subject.Name, info)
            }
        }
    }

    sortTable()
    mergeAccounts()

    // return VALUES that processed USERLIST
    return USERLIST, nil
}

func addToTable(name string, info BindingInfo) {
    for i, account := range USERLIST {
        if account.Name == name {
            USERLIST[i].Bindings = append(account.Bindings, info)
            return
        }
    }
    USERLIST = append(USERLIST, AccountInfo{Name: name, Bindings: []BindingInfo{info}})
}

func sortTable() {
    sort.Slice(USERLIST, func(i, j int) bool {
        if USERLIST[i].Name != USERLIST[j].Name {
            return USERLIST[i].Name < USERLIST[j].Name
        }
        for k := range USERLIST[i].Bindings {
            if USERLIST[i].Bindings[k].Kind != USERLIST[j].Bindings[k].Kind {
                return USERLIST[i].Bindings[k].Kind < USERLIST[j].Bindings[k].Kind
            }
            if USERLIST[i].Bindings[k].Namespace != USERLIST[j].Bindings[k].Namespace {
                return USERLIST[i].Bindings[k].Namespace < USERLIST[j].Bindings[k].Namespace
            }
            if USERLIST[i].Bindings[k].RoleRefName != USERLIST[j].Bindings[k].RoleRefName {
                return USERLIST[i].Bindings[k].RoleRefName < USERLIST[j].Bindings[k].RoleRefName
            }
            if USERLIST[i].Bindings[k].RoleRefKind != USERLIST[j].Bindings[k].RoleRefKind {
                return USERLIST[i].Bindings[k].RoleRefKind < USERLIST[j].Bindings[k].RoleRefKind
            }
        }
        return false
    })
}

func mergeAccounts() {
    for i := 0; i < len(USERLIST); i++ {
        for j := i + 1; j < len(USERLIST); j++ {
            if USERLIST[i].Name == USERLIST[j].Name {
                USERLIST[i].Bindings = append(USERLIST[i].Bindings, USERLIST[j].Bindings...)
                USERLIST = append(USERLIST[:j], USERLIST[j+1:]...)
                j--
            }
        }
    }
}



func attachExtra(accounts []AccountInfo, refinedClusterRoles []Role, refinedRoles []Role) []AccountInfo {
    for i, account := range accounts {
        for j, binding := range account.Bindings {
            if binding.RoleRefKind == "Role" {
                for _, role := range refinedRoles {
                    if role.Metadata.Name == binding.RoleRefName {
                        accounts[i].Bindings[j].ExtraRules = append(binding.ExtraRules, role.Rules...)
                        break
                    }
                }
            } else if binding.RoleRefKind == "ClusterRole" {
                for _, clusterRole := range refinedClusterRoles {
                    if clusterRole.Metadata.Name == binding.RoleRefName {
                        accounts[i].Bindings[j].ExtraRules = append(binding.ExtraRules, clusterRole.Rules...)
                        break
                    }
                }
            }
        }
    }
    return accounts
}

func displayProcessedTable(accounts []AccountInfo, flags InputFlags) {
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)

    if flags.MoreOption {
        fmt.Fprintln(w, "Account Name\tKind\tNamespace\tRoleRefName\tRoleRefKind\tapiGroups\tResources\tVerbs")
        fmt.Fprintln(w, "------------\t----\t---------\t-----------\t-----------\t---------\t---------\t-----")
    } else {
        fmt.Fprintln(w, "Account Name\tKind\tNamespace\tRoleRefName\tRoleRefKind")
        fmt.Fprintln(w, "------------\t----\t---------\t-----------\t-----------")
    }

    prevAccountName := ""
    prevRoleRefName := ""
    prevBindingNamespace := ""

    for _, account := range accounts {
        displayAccountName := true

        for _, binding := range account.Bindings {
            if flags.MoreOption && (binding.RoleRefName != prevRoleRefName || binding.Namespace != prevBindingNamespace) && prevRoleRefName != "" {
                if account.Name == prevAccountName {
                    fmt.Fprintln(w, "\t----\t---------\t-----------\t-----------\t---------\t---------\t-----")
                } else {
                    fmt.Fprintln(w, "------------\t----\t---------\t-----------\t-----------\t---------\t---------\t-----")
                }
            }

            if displayAccountName {
                fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s", account.Name, binding.Kind, binding.Namespace, binding.RoleRefName, binding.RoleRefKind)
                displayAccountName = false
            } else {
                fmt.Fprintf(w, "\t%s\t%s\t%s\t%s", binding.Kind, binding.Namespace, binding.RoleRefName, binding.RoleRefKind)
            }

            if flags.MoreOption && len(binding.ExtraRules) > 0 {
                rule := binding.ExtraRules[0] // start with the first rule
                fmt.Fprintf(w, "\t%s\t%s\t[%s]\n", rule.APIGroups[0], rule.Resources[0], strings.Join(rule.Verbs, ", "))

                for _, rule := range binding.ExtraRules[1:] { // skip the first rule since we already displayed it
                    for _, apiGroup := range rule.APIGroups {
                        for _, resource := range rule.Resources {
                            fmt.Fprintf(w, "\t\t\t\t\t%s\t%s\t[%s]\n", apiGroup, resource, strings.Join(rule.Verbs, ", "))
                        }
                    }
                }
            } else {
                fmt.Fprintln(w)
            }

            prevRoleRefName = binding.RoleRefName // 현재 RoleRefName을 저장
            prevAccountName = account.Name        // 현재 Account Name을 저장
            prevBindingNamespace = binding.Namespace // 현재 Namespace를 저장
        }

        if !flags.MoreOption {
            fmt.Fprintln(w, "------------\t----\t---------\t-----------\t-----------")
        }
    }
    w.Flush()
}


func saveAsCSV(accounts []AccountInfo, flags InputFlags) {
    var filename string

    if flags.MoreOption {
        filename = "userListExtended.csv"
    } else {
        filename = "userList.csv"
    }

    file, err := os.Create(filename)
    if err != nil {
        log.Fatal("Cannot create file", err)
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    if flags.MoreOption {
        writer.Write([]string{"Account Name", "Kind", "Namespace", "RoleRefName", "RoleRefKind", "apiGroups", "Resources", "Verbs"})
    } else {
        writer.Write([]string{"Account Name", "Kind", "Namespace", "RoleRefName", "RoleRefKind"})
    }

    for _, account := range accounts {
        for _, binding := range account.Bindings {
            var record []string
            record = append(record, account.Name, binding.Kind, binding.Namespace, binding.RoleRefName, binding.RoleRefKind)

            if flags.MoreOption && len(binding.ExtraRules) > 0 {
                rule := binding.ExtraRules[0]
                record = append(record, rule.APIGroups[0], rule.Resources[0], strings.Join(rule.Verbs, ", "))
                writer.Write(record) 

                // Handling subsequent rules similar to displayProcessedTable
                for _, rule := range binding.ExtraRules[1:] {
                    for _, apiGroup := range rule.APIGroups {
                        for _, resource := range rule.Resources {
                            writer.Write([]string{"", "", "", "", "", apiGroup, resource, strings.Join(rule.Verbs, ", ")})
                        }
                    }
                }
            } else {
                writer.Write(record)
            }
        }
    }
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
        processedBindings, err := processBindings(refinedClusterRoles, refinedRoles, refinedClusterBindings, refinedRoleBindings)
        if err != nil {
            fmt.Println("Error processing bindings:", err)
            return
        }
        if flags.MoreOption {
            processedBindings = attachExtra(processedBindings, refinedClusterRoles, refinedRoles)
        }
	
	if flags.CSVWrite {
		saveAsCSV(processedBindings, flags)
	} else {
	        displayProcessedTable(processedBindings, flags)
	}
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
