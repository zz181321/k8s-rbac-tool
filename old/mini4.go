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
)

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
	ResourceVersion    string            `json:"resourceVersion"`
	UID                string            `json:"uid"`
}

type RoleRule struct {
	APIGroups     []string `json:"apiGroups"`
	ResourceNames []string `json:"resourceNames,omitempty"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
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

// merge Verbs
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

		// 리소스를 오름차순으로 정렬
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
func isSystemRole(roleName string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(roleName, prefix) {
			return true
		}
	}
	return false
}

func displayUsage() {
	fmt.Println("Usage:")
	fmt.Println("./rbac-tool --table clusterrole       Display cluster roles in a table format.")
	fmt.Println("./rbac-tool --table clusterrole --nosys  Display cluster roles in a table format excluding default system Cluster Roles.")
	fmt.Println("./rbac-tool --verbs                   Display all available verbs from api-resources.")
}

func main() {
	systemPrefixes := []string{"system:", "kubeadm:", "calico"} 

	var tableOption string
	var excludeSystem bool
	var verbsOption bool
	flag.StringVar(&tableOption, "table", "", "Display roles in a table format (use 'clusterrole')")
	flag.BoolVar(&excludeSystem, "nosys", false, "Exclude default system Cluster Roles")
	flag.BoolVar(&verbsOption, "verbs", false, "Display all available verbs from api-resources")
	flag.Parse()
	
	
	if tableOption == "" {
        	displayUsage()
	        return
	    }


	output, err := exec.Command("kubectl", "get", "clusterroles", "-o", "json").Output()
	if err != nil {
		panic(err)
	}

	if tableOption == "" {
		displayUsage()
		return
	}

	if tableOption != "clusterrole" {
		fmt.Println("Invalid table option. Expected 'clusterrole'.")
		return
	}
	if verbsOption {
		cmd := exec.Command("sh", "-c", "kubectl api-resources --no-headers --sort-by name -o wide | sed 's/.*\\[//g' | tr -d \"]\" | tr \" \" \"\\n\" | sort | uniq")
		output, err := cmd.Output()
		if err != nil {
			fmt.Println("Error executing the command:", err)
			return
		}
		fmt.Println(string(output))
		return
	}

	var rolesList struct {
	    Items []Role `json:"items"`
	}

	err = json.Unmarshal(output, &rolesList)
	if err != nil {
		panic(err)
	}

	//sort apiGroups, and merge Verbs
	for i := range rolesList.Items {
		rolesList.Items[i].Rules = mergeRules(rolesList.Items[i].Rules)
		sort.Sort(SortByAPIGroup(rolesList.Items[i].Rules))
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "Kind\tRole (Name)\tapiGroups\tResources\tVerbs")
	fmt.Fprintln(w, "-----------\t---------\t----------\t---------\t------")

	for _, role := range rolesList.Items {
		if excludeSystem && isSystemRole(role.Metadata.Name, systemPrefixes) {
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
			fmt.Fprintln(w, "-----------\t---------\t----------\t---------\t------")
		}
	}

	w.Flush()
}
