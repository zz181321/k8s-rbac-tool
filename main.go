package main

import (
    "fmt"
    "os"
)

func main() {
 // Check command line arguments
    if len(os.Args) < 3 || os.Args[1] != "--list" {
        fmt.Println("Usage: --list <roles|binds|users>")
        return
    }



    switch os.Args[2] {
    
case "roles":
    allRoles := fetchRoles()
    allClusterRoles := fetchClusterRoles()

    
// Print Roles
fmt.Println("----- Roles -----")
for idx, role := range allRoles.Roles {
    fmt.Printf("Type: %s\n[%d] Name: %s\n", role.Type, idx+1, role.Metadata.Name)
    groupIdx := 0
    for _, rule := range role.Rules {
        apiGroups := replaceCoreAPI(rule.APIGroups)
        for _, group := range apiGroups {
            groupIdx++
            fmt.Printf("[%d]APIGroups : %s\n", groupIdx, group)
        }
        fmt.Printf("Resources: %v, Verbs: %v\n", rule.Resources, rule.Verbs)
    }
    fmt.Println("-----------------")
}

// Print ClusterRoles
fmt.Println("----- ClusterRoles -----")
for idx, clusterRole := range allClusterRoles.Roles {
    fmt.Printf("Type: %s\n[%d] Name: %s\n", clusterRole.Type, idx+1, clusterRole.Metadata.Name)
    groupIdx := 0  
    for _, rule := range clusterRole.Rules {
        apiGroups := replaceCoreAPI(rule.APIGroups)
        for _, group := range apiGroups {
            groupIdx++
            fmt.Printf("[%d]APIGroups : %s\n", groupIdx, group)
        }
        fmt.Printf("Resources: %v, Verbs: %v\n", rule.Resources, rule.Verbs)
    }
    fmt.Println("-----------------------")
}

    case "binds":
        all_roleBindings := fetchRoleBindings()
        all_clusterRoleBindings := fetchClusterRoleBindings()

        // Print RoleBindings
        fmt.Println("----- RoleBindings -----")
        for idx, rb := range all_roleBindings.RoleBindings {
            fmt.Printf("Kind: %s\n[%d] Name: %s\nNamespace: %s\nRoleRef: kind: %s, name: %s\n", rb.Kind, idx+1, rb.Metadata.Name, rb.Metadata.Namespace, rb.RoleRef.Kind, rb.RoleRef.Name)
            for subjIdx, subj := range rb.Subjects {
                fmt.Printf("Subject [%d] Kind: %s, Name: %s\n", subjIdx+1, subj.Kind, subj.Name)
            }
            if len(rb.Metadata.OwnerRefs) > 0 {
                for _, owner := range rb.Metadata.OwnerRefs {
                    fmt.Printf("Owner APIVersion: %s, Kind: %s, Name: %s\n", owner.APIVersion, owner.Kind, owner.Name)
                }
            }
            fmt.Println("------------------------")
        }

        // Print ClusterRoleBindings
        fmt.Println("----- ClusterRoleBindings -----")
        for idx, crb := range all_clusterRoleBindings.RoleBindings {
            fmt.Printf("Kind: %s\n[%d] Name: %s\nRoleRef: kind: %s, name: %s\n", crb.Kind, idx+1, crb.Metadata.Name, crb.RoleRef.Kind, crb.RoleRef.Name)
            for subjIdx, subj := range crb.Subjects {
                fmt.Printf("Subject [%d] Kind: %s, Name: %s\n", subjIdx+1, subj.Kind, subj.Name)
            }
            if len(crb.Metadata.OwnerRefs) > 0 {
                for _, owner := range crb.Metadata.OwnerRefs {
                    fmt.Printf("Owner APIVersion: %s, Kind: %s, Name: %s\n", owner.APIVersion, owner.Kind, owner.Name)
                }
            }
            fmt.Println("-----------------------------")
        }

case "users":
        all_roleBindings := fetchRoleBindings()
        all_clusterRoleBindings := fetchClusterRoleBindings()
        allRoles := fetchRoles()
        allClusterRoles := fetchClusterRoles()

        populateAccountList(all_roleBindings.RoleBindings)
        populateAccountList(all_clusterRoleBindings.RoleBindings)

        updateAccountListWithRoles(allRoles.Roles)
        updateAccountListWithRoles(allClusterRoles.Roles)

        // printAccountList() is not yet implemented
        printAccountList()

    default:
        fmt.Println("Invalid value provided. Use 'roles', 'binds', or 'users'.")
    }

}
