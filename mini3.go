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


// find and merge Verbs
func mergeVerbsByResource(rules []RoleRule) map[string][]string {
	resourceVerbs := make(map[string][]string)

	for _, rule := range rules {
		for _, resource := range rule.Resources {
			if _, ok := resourceVerbs[resource]; !ok {
				resourceVerbs[resource] = make([]string, 0)
			}
			resourceVerbs[resource] = append(resourceVerbs[resource], rule.Verbs...)
		}
	}

	for resource, verbs := range resourceVerbs {
		uniqueVerbs := removeDuplicates(verbs)
		resourceVerbs[resource] = uniqueVerbs
	}

	return resourceVerbs
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for _, v := range elements {
		if encountered[v] == false {
			encountered[v] = true
			result = append(result, v)
		}
	}
	return result
}

func isCompleteVerbs(verbs []string) bool {
	completeSet := []string{"get", "list", "watch", "create", "delete", "deletecollection", "patch", "update"}
	for _, v := range completeSet {
		if !contains(verbs, v) {
			return false
		}
	}
	return true
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

type ByResource []Rule

func (r ByResource) Len() int {
	return len(r)
}

func (r ByResource) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r ByResource) Less(i, j int) bool {
	return r[i].Resources[0] < r[j].Resources[0]
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
}


func main() {
	excludePrefixes := []string{"system:", "kubeadm:", "calico"}

	var tableOption string
	var excludeSystem bool
	flag.StringVar(&tableOption, "table", "", "Display roles in a table format (use 'role')")
	flag.BoolVar(&excludeSystem, "nosys", false, "Exclude roles that are default system roles")
	flag.Parse()

	out, err := exec.Command("kubectl", "get", "roles", "-o", "json").Output()
	if err != nil {
		panic(err)
	}

	var rolesList struct {
		Items []Role `json:"items"`
	}

	err = json.Unmarshal(out, &rolesList)
	if err != nil {
		panic(err)
	}

	// Sorting
	for i := range rolesList.Items {
		sort.Sort(ByResource(rolesList.Items[i].Rules))
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Kind\tRole Name\tapiGroup\tResource\tVerbs")
	fmt.Fprintln(w, "-----------\t-----\t--------\t--------\t-----")

	for _, role := range rolesList.Items {
		if excludeSystem && isSystemRole(role.Metadata.Name, excludePrefixes) {
			continue
		}

		resourceVerbsMap := mergeVerbsByResource(role.Rules)

		displayedHeader := false
		for resource, verbs := range resourceVerbsMap {
			displayVerb := strings.Join(verbs, ", ")
			if isCompleteVerbs(verbs) {
				displayVerb = "*"
			}
			if !displayedHeader {
				fmt.Fprintf(w, "%s\t%s\t\t%s\t [%s]\n", role.Kind, role.Metadata.Name, resource, displayVerb)
				displayedHeader = true
			} else {
				fmt.Fprintf(w, "\t\t\t%s\t [%s]\n", resource, displayVerb)
			}
		}

		if displayedHeader {
			fmt.Fprintln(w, "-----------\t-----\t--------\t--------\t-----")
		}
	}

	w.Flush()
}

