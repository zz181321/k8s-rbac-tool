package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"text/tabwriter"
	"strings"
	"flag"
)

type ClusterRole struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Metadata   ClusterMeta  `json:"metadata"`
	Rules      []ClusterRule `json:"rules"`
}

type ClusterMeta struct {
	Annotations        map[string]string `json:"annotations"`
	CreationTimestamp  string            `json:"creationTimestamp"`
	Labels             map[string]string `json:"labels"`
	Name               string            `json:"name"`
	ResourceVersion    string            `json:"resourceVersion"`
	UID                string            `json:"uid"`
}

type ClusterRule struct {
	APIGroups     []string `json:"apiGroups"`
	ResourceNames []string `json:"resourceNames,omitempty"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
}

func main() {
	var nosys bool
	flag.BoolVar(&nosys, "nosys", false, "Exclude roles that default system Cluster Roles")
	flag.Parse()

	out, err := exec.Command("kubectl", "get", "clusterroles", "-o", "json").Output()
	if err != nil {
		panic(err)
	}

var clusterRolesList struct {
    Items []ClusterRole `json:"items"`
}


err = json.Unmarshal(out, &clusterRolesList)
if err != nil {
    panic(err)
}


w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
fmt.Fprintln(w, "Kind\tRole (Name)\tapiGroups\tResources\tVerbs")
fmt.Fprintln(w, "-----------\t----------\t---------\t---------\t-----")

for _, role := range clusterRolesList.Items {
	if nosys && strings.HasPrefix(role.Metadata.Name, "system:") || strings.HasPrefix(role.Metadata.Name, "kubeadm:") {
	continue
	}
    printedHeaderForRole := false // 헤더를 이미 출력했는지 체크
    for _, rule := range role.Rules {
        for _, apiGroup := range rule.APIGroups {
            for _, resource := range rule.Resources {
                if !printedHeaderForRole {
                    fmt.Fprintf(w, "%s\t%s\t%s\t%s\t[%s]\n", role.Kind, role.Metadata.Name, apiGroup, resource, strings.Join(rule.Verbs, ", "))
                    printedHeaderForRole = true
                } else {
                    fmt.Fprintf(w, "\t\t%s\t%s\t[%s]\n", apiGroup, resource, strings.Join(rule.Verbs, ", "))
                }
            }
        }
    }
    if printedHeaderForRole { // 만약 규칙이 있으면 구분자 출력
        fmt.Fprintln(w, "-----------\t----------\t---------\t---------\t-----")
    }
}

w.Flush()
}
