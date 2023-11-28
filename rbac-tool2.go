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

const Version = "0.6.0"

type InputFlags struct {
    CommandType       string // "show" or "get"
    ResourceType      string // "user" or "csv"
    TableType         string // K8s roles and bindings, plus KubeSphere roles and bindings
    CSVType           string
    ExcludeSystem     bool // --nosys
    ExtendedOption    bool // --extended or -ext
    MoreOption        bool // --more
    Service           bool // --service
    KubeSphere        bool // Is it KubeSphere specific? (or not KubeSphere)
    OnlyOption        []string // --only with parameters: decide what kind of role you want to print.
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
    Namespace          string            `json:"namespace,omitempty"`
    ResourceVersion    string            `json:"resourceVersion"`
    UID                string            `json:"uid"`
}
type RoleRule struct {
    APIGroups     []string `json:"apiGroups"`
    ResourceNames []string `json:"resourceNames,omitempty"`
    Resources     []string `json:"resources"`
    Verbs         []string `json:"verbs"`
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
    OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
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

// it's a custom field from KubeSphere
type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller,omitempty"`
	BlockOwnerDeletion *bool `json:"blockOwnerDeletion,omitempty"`
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
    Name     	  string        `json:"name"`
    Type          string        `json:"kind"`
    Bindings	  []BindingInfo `json:"bindings"`
}

var USERLIST []AccountInfo



func parseInputFlags() InputFlags {
    var flags InputFlags

    flag.Parse()
    args := flag.Args()

    if len(args) == 0 {
        fmt.Println("No arguments provided.\n")
        displayUsage()
        os.Exit(1)
    }

    if len(args) == 1 && args[0] == "version" {
        fmt.Println("RBAC Tool Version:", Version)
        os.Exit(0)
    }

    switch args[0] {
    case "show":
        flags.CommandType = "show"
        if len(args) > 1 {
            switch args[1] {
	    case "role", "rolebinding", "clusterrole", "clusterrolebinding":
		flags.ResourceType = "table"
		flags.TableType = args[1]
            case "kubesphere":
                if len(args) > 2 {
		    flags.KubeSphere = true
		    switch args[2] {
		    case "workspacerole", "workspacerolebinding", "globalrole", "globalrolebinding":
			flags.ResourceType = "table"
			flags.TableType = args[2]
		    default:
			fmt.Println("Invalid table type for 'show kubesphere'.")
			os.Exit(1)
		    }
                } else {
                    fmt.Println("Expected a table type argument after 'show kubesphere'.")
                    os.Exit(1)
                }
            case "core":
                flags.ResourceType = "core"
            case "verbs":
                flags.ResourceType = "verbs"
            default:
                fmt.Println("Invalid resource type provided for 'show'.")
                os.Exit(1)
            }
        } else {
            fmt.Println("Expected a resource type argument after 'show'.")
            os.Exit(1)
        }
    case "get":
        flags.CommandType = "get"
        if len(args) > 1 {
            flags.ResourceType = args[1]
        } else {
            fmt.Println("Expected a resource type argument after 'get'.")
            os.Exit(1)
        }
    default:
        fmt.Println("Invalid command type provided.")
        os.Exit(1)
    }

    for i, arg := range args {
        switch arg {
        case "--nosys":
            flags.ExcludeSystem = true
        case "--extended", "-ext":
            flags.ExtendedOption = true
        case "--more":
            flags.MoreOption = true
        case "--service":
            flags.Service = true
	case "--kubesphere", "-ks":
	    flags.KubeSphere = true
        case "--only":
            if i+1 < len(args) {
                value := args[i+1]
                onlyOptions := strings.Split(value, ",") // 쉼표로 구분된 값들을 분리
                for _, option := range onlyOptions {
                    option = strings.TrimSpace(option) // 공백 제거
                    // 유효한 옵션인지 확인
                    if option == "rolebinding" || option == "clusterrolebinding" || option == "workspacerolebinding" || option == "globalrolebinding" {
                        flags.OnlyOption = append(flags.OnlyOption, option)
                    } else {
                        fmt.Printf("Invalid value provided after '--only' option: '%s'.\n", option)
                        os.Exit(1)
                    }
                }
                i++ // skip the next argument (다음 인수 건너뛰기)
            } else {
                fmt.Println("Expected a value after '--only' option.")
                os.Exit(1)
            }
        case "csv":
            if i+1 < len(args) {
                flags.CSVType = args[i+1]
            } else {
                fmt.Println("Expected a resource type for 'csv'.")
                os.Exit(1)
            }
        }
    }

    return flags
}

func displayUsage() {
    fmt.Println("+-----------------------------------------------------------------------------------+")
    fmt.Println("|                                    RBAC Tool Usage                                |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| View a list of user permissions in Kubernetes                                     |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| show role [--nosys]                                                               |")
    fmt.Println("| show rolebinding [--nosys]                                                        |")
    fmt.Println("| show clusterrole [--nosys]                                                        |")
    fmt.Println("| show clusterrolebinding [--nosys] [--extended | -ext]                             |")
    fmt.Println("|                                                                                   |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| View a list of user permissions added by Kubesphere                               |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| show kubesphere workspacerole [--nosys]                                           |")
    fmt.Println("| show kubesphere workspacerolebinding [--nosys]                                    |")
    fmt.Println("| show kubesphere globalrole [--nosys]                                              |")
    fmt.Println("| show kubesphere globalrolebinding [--nosys]                                       |")
    fmt.Println("|                                                                                   |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| Get a list of user priviliges in Kubernetes, reordered around user accounts.      |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| get user [--more] [--service] [--only (with parameters)]                          |")
    fmt.Println("|                                                                                   |")
    fmt.Println("| --only option can take multiple values, separated by commas.                      |")
    fmt.Println("| the parameters: rolebinding, clusterrolebinding, workspacebinding, globalbinding  |")
    fmt.Println("|                                                                                   |")
    fmt.Println("| Example:                                                                          |")
    fmt.Println("| get user --more --service --only rolebinding, clusterrolebinding                  |")
    fmt.Println("|                                                                                   |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| Save a list of user priviliges in Kubernetes as a CSV file.                       |")
    fmt.Println("|-----------------------------------------------------------------------------------|")
    fmt.Println("| get csv user [ (The options are the same as those for 'get user'.) ]              |")
    fmt.Println("|                                                                                   |")
    fmt.Println("| Example:                                                                          |")
    fmt.Println("| get csv user --more --service --only rolebinding, clusterrolebinding              |")
    fmt.Println("+-----------------------------------------------------------------------------------+")
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

            // 만약 resourceNames이 존재한다면 resource를 변경
            if len(rule.ResourceNames) > 0 {
                resource = fmt.Sprintf("%s.%s", resource, rule.ResourceNames[0]) // 여기서는 ResourceNames 중 첫 번째 것만을 사용
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

// Collects all Roles and Cluster Roles. In addition, it also collects Workspace Roles and Global Roles. It's the Kubesphere-specific role type.
func storeKubernetesRoles(roleType string) ([]Role, error) {
    var cmd *exec.Cmd

    switch roleType {
    case "roles":
        cmd = exec.Command("kubectl", "get", "roles", "-A", "-o", "json")
    case "workspaceroles":
        cmd = exec.Command("kubectl", "get", "workspaceroles", "-A", "-o", "json")
    case "clusterroles":
        cmd = exec.Command("kubectl", "get", "clusterroles", "-o", "json")
    case "globalroles":
        cmd = exec.Command("kubectl", "get", "globalroles", "-o", "json")
    default:
        return nil, fmt.Errorf("Invalid role type: %s", roleType)
    }

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


func storeBindings(resourceType string) ([]RoleBinding, error) {
    var cmd *exec.Cmd

    switch resourceType {
    case "clusterrolebindings":
        cmd = exec.Command("kubectl", "get", "clusterrolebindings", "-o", "json")
    case "rolebindings":
        cmd = exec.Command("kubectl", "get", "rolebindings", "-A", "-o", "json")
    case "workspacerolebindings":
        cmd = exec.Command("kubectl", "get", "workspacerolebindings", "-A", "-o", "json")
    case "globalrolebindings":
        cmd = exec.Command("kubectl", "get", "globalrolebindings", "-o", "json")
    default:
        return nil, fmt.Errorf("invalid resource type: %s", resourceType)
    }

    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    var bindingsList struct {
        Items []RoleBinding `json:"items"`
    }

    err = json.Unmarshal(output, &bindingsList)
    if err != nil {
        return nil, err
    }

    return bindingsList.Items, nil
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
			// if it's a Workspace(a Concept from Kubesphere), do this, because the 'workspace' is not described in Metadata.Namespace
			workspaceName, exists := role.Metadata.Labels["kubesphere.io/workspace"]
			if exists {
	                        fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t [%s]\n", workspaceName, role.Kind, role.Metadata.Name, apiGroup, resource, strings.Join(rule.Verbs, ", "))
        	                displayedHeader = true
			    } else {
	                        fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t [%s]\n", role.Metadata.Namespace, role.Kind, role.Metadata.Name, apiGroup, resource, strings.Join(rule.Verbs, ", "))
        	                displayedHeader = true
			    }
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


func displayClusterRoleBindings(bindings []RoleBinding, flags InputFlags, systemPrefixes []string) {
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
		// if it's a Workspace(a Concept from Kubesphere) do this. because the "workspace" is not describe in Metadata.Namespace
		workspaceName, exists := binding.Metadata.Labels["kubesphere.io/workspace"]
		if exists {
		    fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", binding.Kind, binding.Metadata.Name, workspaceName, binding.RoleRef.Kind, binding.RoleRef.Name, subject.Kind, subject.Name, namespace)
		} else {
		    fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", binding.Kind, binding.Metadata.Name, binding.Metadata.Namespace, binding.RoleRef.Kind, binding.RoleRef.Name, subject.Kind, subject.Name, namespace)
		}

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

func processBindings(clusterRoles []Role, roles []Role, clusterRoleBindings []RoleBinding, roleBindings []RoleBinding, flags InputFlags) ([]AccountInfo, error) {
    // 초기화: USERLIST
    USERLIST = []AccountInfo{}
    containsRoleBinding := false
    containsClusterRoleBinding := false
    containsWorkspaceRoleBinding := false
    containsGlobalRoleBinding := false
    
    for _, option:= range flags.OnlyOption {
	if option == "rolebinding" {
	    containsRoleBinding = true
	} else if option == "clusterrolebinding" {
	    containsClusterRoleBinding = true 
	} else if option == "workspacerolebinding" {
	    containsWorkspaceRoleBinding = true
	} else if option == "globalrolebinding" {
	    containsGlobalRoleBinding = true
	}
    }

	

    // ClusterRoleBinding 데이터 처리
    // if flags.OnlyOption == "" || flags.OnlyOption == "clusterrolebinding" {
    if len(flags.OnlyOption) == 0 || containsClusterRoleBinding {
	for _, clusterBinding := range clusterRoleBindings {
            for _, subject := range clusterBinding.Subjects {
//	    if subject.Kind == "User" && (!excludeSystem || !strings.HasPrefix(subject.Name, "system:")){
//	    if subject.Kind == "User" && !strings.HasPrefix(subject.Name, "system:"){
	        if subject.Kind == "User" || flags.Service && subject.Kind == "ServiceAccount" {
                    info := BindingInfo{
                        Kind:        clusterBinding.Kind,
                        RoleRefName: clusterBinding.RoleRef.Name,
                        RoleRefKind: clusterBinding.RoleRef.Kind,
                    }
                    addToTable(subject.Name, subject.Kind, info)
                }
            }
        }
    }

    // RoleBinding 데이터 처리
    //if flags.OnlyOption == "" || flags.OnlyOption == "rolebinding" {
    if len(flags.OnlyOption) == 0 || containsRoleBinding {
        for _, roleBinding := range roleBindings {
            for _, subject := range roleBinding.Subjects {
//	    if subject.Kind == "User" && (!excludeSystem || !strings.HasPrefix(subject.Name, "system:")){
//	    if subject.Kind == "User" && !strings.HasPrefix(subject.Name, "system:"){
	        if subject.Kind == "User" || flags.Service && subject.Kind == "ServiceAccount" {
                    info := BindingInfo{
                        Kind:        roleBinding.Kind,
                        Namespace:   roleBinding.Metadata.Namespace,
                        RoleRefName: roleBinding.RoleRef.Name,
                        RoleRefKind: roleBinding.RoleRef.Kind,
                    }
                    addToTable(subject.Name, subject.Kind, info)
                }
            }
        }
    }

    if len(flags.OnlyOption) == 0 || containsWorkspaceRoleBinding {
	for _, clusterBinding := range workspaceRoleBindings {
            for _, subject := range clusterBinding.Subjects {
	        if subject.Kind == "User" || flags.Service && subject.Kind == "ServiceAccount" {
                    info := BindingInfo{
                        Kind:        clusterBinding.Kind,
                        RoleRefName: clusterBinding.RoleRef.Name,
                        RoleRefKind: clusterBinding.RoleRef.Kind,
                    }
                    addToTable(subject.Name, subject.Kind, info)
                }
            }
        }
    }

    if len(flags.OnlyOption) == 0 || containsGlobalRoleBinding {
	for _, clusterBinding := range globalRoleBindings {
            for _, subject := range clusterBinding.Subjects {
	        if subject.Kind == "User" || flags.Service && subject.Kind == "ServiceAccount" {
                    info := BindingInfo{
                        Kind:        clusterBinding.Kind,
                        RoleRefName: clusterBinding.RoleRef.Name,
                        RoleRefKind: clusterBinding.RoleRef.Kind,
                    }
                    addToTable(subject.Name, subject.Kind, info)
                }
            }
        }
    }


    sortTable()
    mergeAccounts()

    // return VALUES that processed USERLIST
    return USERLIST, nil
}

func addToTable(name string, kind string, info BindingInfo) {
    for i, account := range USERLIST {
        if account.Name == name {
            USERLIST[i].Bindings = append(account.Bindings, info)
            return
        }
    }
    USERLIST = append(USERLIST, AccountInfo{Name: name, Type: kind, Bindings: []BindingInfo{info}})
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
        fmt.Fprintln(w, "Account Name\tID Type\tKind\tNamespace\tRoleRefName\tRoleRefKind\tapiGroups\tResources\tVerbs")
        fmt.Fprintln(w, "------------\t-------\t----\t---------\t-----------\t-----------\t---------\t---------\t-----")
    } else {
        fmt.Fprintln(w, "Account Name\tID Type\tKind\tNamespace\tRoleRefName\tRoleRefKind")
        fmt.Fprintln(w, "------------\t-------\t----\t---------\t-----------\t-----------")
    }

    prevAccountName := ""
    prevRoleRefName := ""
    prevBindingNamespace := ""

    for _, account := range accounts {
        displayAccountName := true

        for _, binding := range account.Bindings {
            if flags.MoreOption && (binding.RoleRefName != prevRoleRefName || binding.Namespace != prevBindingNamespace) && prevRoleRefName != "" {
                if account.Name == prevAccountName {
                    fmt.Fprintln(w, "\t\t----\t---------\t-----------\t-----------\t---------\t---------\t-----")
                } else {
                    fmt.Fprintln(w, "------------\t-------\t----\t---------\t-----------\t-----------\t---------\t---------\t-----")
                }
            }

	    // "ServiceAccount" to "Service", for short name
            var idType string
            if account.Type == "ServiceAccount" {
                idType = "Service"
            } else {
                idType = account.Type
            }

            if displayAccountName {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s", account.Name, idType, binding.Kind, binding.Namespace, binding.RoleRefName, binding.RoleRefKind)
                displayAccountName = false
            } else {
                fmt.Fprintf(w, "\t\t%s\t%s\t%s\t%s", binding.Kind, binding.Namespace, binding.RoleRefName, binding.RoleRefKind)
            }

            if flags.MoreOption && len(binding.ExtraRules) > 0 {
                rule := binding.ExtraRules[0] // start with the first rule
                fmt.Fprintf(w, "\t%s\t%s\t[%s]\n", rule.APIGroups[0], rule.Resources[0], strings.Join(rule.Verbs, ", "))

                for _, rule := range binding.ExtraRules[1:] { // skip the first rule since we already displayed it
                    for _, apiGroup := range rule.APIGroups {
                        for _, resource := range rule.Resources {
                            fmt.Fprintf(w, "\t\t\t\t\t\t%s\t%s\t[%s]\n", apiGroup, resource, strings.Join(rule.Verbs, ", "))
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
            fmt.Fprintln(w, "------------\t-------\t----\t---------\t-----------\t-----------")
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
        writer.Write([]string{"Account Name", "Account Type", "Kind", "Namespace", "RoleRefName", "RoleRefKind", "apiGroups", "Resources", "Verbs"})
    } else {
        writer.Write([]string{"Account Name", "Account Type", "Kind", "Namespace", "RoleRefName", "RoleRefKind"})
    }

    for _, account := range accounts {
        for _, binding := range account.Bindings {
            var record []string
            record = append(record, account.Name, account.Type, binding.Kind, binding.Namespace, binding.RoleRefName, binding.RoleRefKind)

            if flags.MoreOption && len(binding.ExtraRules) > 0 {
                rule := binding.ExtraRules[0]
                record = append(record, rule.APIGroups[0], rule.Resources[0], strings.Join(rule.Verbs, ", "))
                writer.Write(record) 

                // Handling subsequent rules similar to displayProcessedTable
                for _, rule := range binding.ExtraRules[1:] {
                    for _, apiGroup := range rule.APIGroups {
                        for _, resource := range rule.Resources {
                            writer.Write([]string{"","", "", "", "", "", apiGroup, resource, strings.Join(rule.Verbs, ", ")})
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
    var refinedWorkspaceRoles	     []Role
    var refinedGlobalRoles	     []Role
    var refinedWorkspaceRoleBindings []RoleBinding
    var refinedGlobalRoleBindings    []RoleBinding

    flags := parseInputFlags()
//    fmt.Println(flags)

//    systemPrefixes := []string{"system:", "kubeadm:", "calico","kubesphere","ks-","ingress-nginx","notification-manager","unity-","vxflexos"}
    systemPrefixes := []string{"system:", "kubeadm:", "kubesphere","ks-","ingress-nginx","notification-manager","unity-","vxflexos"}
    


    refinedRoles, err := storeKubernetesRoles("roles")
    if err != nil {
        fmt.Println("Error getting Role data:", err)
        return
    }

    refinedClusterRoles, err := storeKubernetesRoles("clusterroles")
    if err != nil {
        fmt.Println("Error getting Cluster Role data:", err)
        return
    }

    refinedClusterBindings, err := storeBindings("clusterrolebindings")
    if err != nil {
        fmt.Println("Error getting Cluster Role Binding data:", err)
        return
    }

    refinedRoleBindings, err := storeBindings("rolebindings")
    if err != nil {
        fmt.Println("Error getting Role Binding data:", err)
        return
    }

    if flags.KubeSphere {
	// := 연산자는 새로운 변수를 선언하고 초기화하는데 사용되므로, 기존에 선언된 변수에 값을 할당하기 위해 = 연산자를 사용
	refinedWorkspaceRoles, err = storeKubernetesRoles("workspaceroles")
	if err != nil {
	fmt.Println("Error getting Kubesphere's Workspace Role data:", err)
        return
	}

	refinedGlobalRoles, err = storeKubernetesRoles("globalroles")
	if err != nil {
	fmt.Println("Error getting Kubesphere's Global Role data:", err)
        return
	}
    
	refinedWorkspaceRoleBindings, err = storeBindings("workspacerolebindings")
	if err != nil {
        fmt.Println("Error getting Workspace Role Binding data:", err)
        return
    	}

	refinedGlobalRoleBindings, err = storeBindings("globalrolebindings")
	if err != nil {
        fmt.Println("Error getting Global Role Binding data:", err)
        return
	}

    }


 switch flags.CommandType {
	case "show":
	    switch flags.ResourceType {
	    case "table":
	        switch flags.TableType {
	        case "clusterrole":
	            displayClusterRoles(refinedClusterRoles, flags, systemPrefixes)
	        case "clusterrolebinding":
	            displayClusterRoleBindings(refinedClusterBindings, flags, systemPrefixes)
	        case "role":
	            displayRoles(refinedRoles, flags, systemPrefixes)
	        case "rolebinding":
	            displayRoleBindings(refinedRoleBindings, flags, systemPrefixes)
		case "globalrole":
	            displayClusterRoles(refinedGlobalRoles, flags, systemPrefixes)
	        case "globalrolebinding":
	            displayRoleBindings(refinedGlobalRoleBindings, flags, systemPrefixes)
	        case "workspacerole":
	            displayRoles(refinedWorkspaceRoles, flags, systemPrefixes)
	        case "workspacerolebinding":
	            displayRoleBindings(refinedWorkspaceRoleBindings, flags, systemPrefixes)
	        default:
	            displayUsage()
	        }
	    case "core":
	        displayCoreResources()
	    case "verbs":
	        displayBuiltInVerbs()
	    default:
	        displayUsage()
	    }
	case "get":
	    switch flags.ResourceType {
	    case "user":
	        processedBindings, err := processBindings(refinedClusterRoles, refinedRoles, refinedClusterBindings, refinedRoleBindings, flags)            
	        if err != nil {
	            fmt.Println("Error processing bindings:", err)
	            return
	        }
		if flags.KubeSphere {
	            processedKubeSphereBindings, err := processBindings(refinedClusterRoles, refinedRoles, refinedWorkspaceRoles, refineGlobalRoles, refinedClusterBindings, refinedRoleBindings, refinedWorkspaceRoleBindings, refinedGlobalRoleBindings, flags)            
	            if err != nil {
	        	fmt.Println("Error processing KubeSphere bindings:", err)
	                return
		    }
		}
	        if flags.MoreOption {
	            processedBindings = attachExtra(processedBindings, refinedClusterRoles, refinedRoles)
	        }
	        displayProcessedTable(processedBindings, flags)
	    case "csv":
	        switch flags.CSVType {
	        case "user":
	            processedBindings, err := processBindings(refinedClusterRoles, refinedRoles, refinedClusterBindings, refinedRoleBindings, flags)
	            if err != nil {
	                fmt.Println("Error processing bindings:", err)
	                return
	            }
	            if flags.MoreOption {
	                processedBindings = attachExtra(processedBindings, refinedClusterRoles, refinedRoles)
	            }
	            saveAsCSV(processedBindings, flags)
	        case "role":
	            //saveAsCSV(refinedRoles, flags)
	        case "rolebinding":
	            //saveAsCSV(refinedRoleBindings, flags)
	        case "clusterrole":
	            //saveAsCSV(refinedClusterRoles, flags)
	        case "clusterrolebinding":
	            //saveAsCSV(refinedClusterBindings, flags)
	        default:
	            displayUsage()
	        }
	    default:
	        displayUsage()
	    }
	default:
	    displayUsage()
	}

//end of main()
}
