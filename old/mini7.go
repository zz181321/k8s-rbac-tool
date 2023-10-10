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
	systemPrefixes := []string{"system:", "kubeadm:", "calico"} 
	var tableOption string
	var excludeSystem bool
	flag.StringVar(&tableOption, "table", "", "Display roles in a table format (use 'clusterrole')")
	flag.BoolVar(&excludeSystem, "nosys", false, "Exclude default system Cluster Roles")
	flag.Parse()

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

	var rolesList struct {
	    Items []Role `json:"items"`
	}

	err = json.Unmarshal(output, &rolesList)
	if err != nil {
		panic(err)
	}

	for i := range rolesList.Items {
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

