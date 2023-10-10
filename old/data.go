package main

import (
  "encoding/json"
  "os/exec"
)


// Role and ClusterRole
type RoleMetadata struct {
    Name string `json:"name"`
}
type Permission struct {
    APIGroups []string `json:"apiGroups"`
    Resources []string `json:"resources"`
    Verbs     []string `json:"verbs"`
}
type RoleInfo struct {
    Type     string       `json:"kind"`
    Metadata RoleMetadata `json:"metadata"`
    Rules    []Permission `json:"rules"`
}
type RoleCollection struct {
    Roles []RoleInfo `json:"items"`
}
type ClusterRoleCollection struct {
    Roles []RoleInfo `json:"items"`
}
// RoleBinding and ClusterRoleBinding
type OwnerReference struct {
    APIVersion string `json:"apiVersion"`
    Kind       string `json:"kind"`
    Name       string `json:"name"`
}
type RoleRef struct {
    Kind string `json:"kind"`
    Name string `json:"name"`
}
type Subject struct {
    Kind string `json:"kind"`
    Name string `json:"name"`
}
type RoleBindingMetadata struct {
    Name      string          `json:"name"`
    Namespace string          `json:"namespace,omitempty"`
    OwnerRefs []OwnerReference `json:"ownerReferences,omitempty"`
}
type RoleBindingInfo struct {
    Kind     string             `json:"kind"`
    Metadata RoleBindingMetadata `json:"metadata"`
    RoleRef  RoleRef            `json:"roleRef"`
    Subjects []Subject          `json:"subjects"`
}
type RoleBindingCollection struct {
    RoleBindings []RoleBindingInfo `json:"items"`
}
type ClusterRoleBindingCollection struct {
    RoleBindings []RoleBindingInfo `json:"items"`
}
type AccountInfo struct {
    Index     int
    Kind      string
    Name      string
    RoleRefKind  string
    RoleRefName  string
    APIGroups    []string
    Resources   []string
    Verbs       []string
}


var account_list []AccountInfo


// Fetch functions
func fetchRoles() RoleCollection {
    output, _ := exec.Command("kubectl", "get", "roles", "-A", "-o", "json").Output()
    var roles RoleCollection
    json.Unmarshal(output, &roles)
    return roles
}
func fetchClusterRoles() ClusterRoleCollection {
    output, _ := exec.Command("kubectl", "get", "clusterroles", "-o", "json").Output()
    var clusterRoles ClusterRoleCollection
    json.Unmarshal(output, &clusterRoles)
    return clusterRoles
}
func fetchRoleBindings() RoleBindingCollection {
    output, _ := exec.Command("kubectl", "get", "rolebindings", "-A", "-o", "json").Output()
    var all_roleBindings RoleBindingCollection
    json.Unmarshal(output, &all_roleBindings)
    return all_roleBindings
}
func fetchClusterRoleBindings() ClusterRoleBindingCollection {
    output, _ := exec.Command("kubectl", "get", "clusterrolebindings", "-o", "json").Output()
    var all_clusterRoleBindings ClusterRoleBindingCollection
    json.Unmarshal(output, &all_clusterRoleBindings)
    return all_clusterRoleBindings
}
func populateAccountList(roleBindings []RoleBindingInfo) {
    for _, rb := range roleBindings {
        for _, subj := range rb.Subjects {
            if subj.Kind == "User" {
                account := AccountInfo{
                    Index:      len(account_list) + 1,
                    Kind:       subj.Kind,
                    Name:       subj.Name,
                    RoleRefKind: rb.RoleRef.Kind,
                    RoleRefName: rb.RoleRef.Name,
                }
                account_list = append(account_list, account)
            }
        }
    }
}
func updateAccountListWithRoles(roles []RoleInfo) {
    for i := range account_list {
        for _, role := range roles {
            if account_list[i].RoleRefName == role.Metadata.Name {
                for _, rule := range role.Rules {
                    account_list[i].APIGroups = append(account_list[i].APIGroups, rule.APIGroups...)
                    account_list[i].Resources = append(account_list[i].Resources, rule.Resources...)
                    account_list[i].Verbs = append(account_list[i].Verbs, rule.Verbs...)
                }
            }
        }
    }
}
