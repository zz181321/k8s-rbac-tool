package main

import (
  "fmt"
)

func replaceCoreAPI(apiGroups []string) []string {
    for i, group := range apiGroups {
        if group == "" {
            apiGroups[i] = "CORE"
        }
    }
    return apiGroups
}

func printAccountList() {
    fmt.Println("Index   User    Kind        Role(Name)  apiGroups   Resources                                    Verbs")

    for _, account := range account_list {
        fmt.Printf("%04d    %s    %s    %s        ", account.Index, account.Name, account.RoleRefKind, account.RoleRefName)

        for idx, group := range replaceCoreAPI(account.APIGroups) {
            if idx != 0 {
                fmt.Printf("                                                  ") // 49 spaces for alignment
            }
            fmt.Printf("%s        ", group)

            if idx < len(account.Resources) {
                fmt.Printf("%-40s", account.Resources[idx]) // pad with spaces to align to a column of width 40
            }

            if idx < len(account.Verbs) {
                fmt.Printf("%v\n", account.Verbs[idx])
            } else {
                fmt.Println()
            }
        }
    }
}
