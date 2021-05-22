// dnscl: Analyze BIND DNS query data from syslog file input
// author: Mark W. Hunter
// https://github.com/mark-w-hunter/dnscl
//
// The MIT License (MIT)
//
// Copyright (c) 2021 Mark W. Hunter
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	filename = "/var/log/syslog" // path to syslog file
	// filename = "/var/log/messages" // path to alternate syslog file
	wildcard = ""
)

// Count is the number of results from a query
type Count struct {
	Key   string
	Value int
}

func dnsclIPaddress(ipAddress string) int {
	startTime := time.Now()
	lineCount := 0
	domainMap := make(map[string]int)
	ipAddressSearch := ipAddress + "#"

	syslogFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err = syslogFile.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	scanner := bufio.NewScanner(syslogFile)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "named") && strings.Contains(scanner.Text(), "query:") {
			if strings.Contains(scanner.Text(), ipAddressSearch) {
				fields := strings.Fields(scanner.Text())
				if len(fields) > 12 {
					domain := fields[8]
					domainMap[domain]++
				}
				lineCount++
			}
		}
	}

	domainMapSorted := sortMap(domainMap)
	elapsedTime := time.Since(startTime).Seconds()

	fmt.Println()
	fmt.Println(ipAddress, "total queries:", lineCount)
	fmt.Println("queries:")

	for _, domainName := range domainMapSorted {
		fmt.Printf("%v \t %v\n", domainName.Value, domainName.Key)
	}

	fmt.Printf("\nSummary: Searched %s and found %d queries for %d domain names.\n", ipAddress, lineCount, len(domainMap))
	fmt.Printf("Query time: %.2f seconds\n", elapsedTime)
	return lineCount
}

func dnsclDomainName(domainName string) int {
	startTime := time.Now()
	lineCount := 0
	ipMap := make(map[string]int)
	domainMap := make(map[string]int)
	domainRegex := regexp.MustCompile("(?i)" + domainName)

	syslogFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err = syslogFile.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	scanner := bufio.NewScanner(syslogFile)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "named") && strings.Contains(scanner.Text(), "query:") {
			match := domainRegex.MatchString(scanner.Text())
			if match {
				fields := strings.Fields(scanner.Text())
				if len(fields) > 12 {
					ipAddrFields := strings.Split(fields[5], "#")
					ipAddr := ipAddrFields[0]
					domainNameField := fields[8]
					ipMap[ipAddr]++
					domainMap[domainNameField]++
				}
				lineCount++
			}
		}
	}

	ipMapSorted := sortMap(ipMap)
	elapsedTime := time.Since(startTime).Seconds()

	fmt.Println()
	fmt.Println(domainName, "total queries:", lineCount)
	fmt.Println("ip addresses:")

	for _, ipAddress := range ipMapSorted {
		fmt.Printf("%v \t %v\n", ipAddress.Value, ipAddress.Key)
	}

	domainKeys := make([]string, 0, len(domainMap))
	for k := range domainMap {
		domainKeys = append(domainKeys, k)
	}
	sort.Strings(domainKeys)

	if domainName != "" {
		fmt.Println("\ndomain names: ")
		for _, domainKey := range domainKeys {
			fmt.Println(domainKey)
		}
	}

	fmt.Printf("\nSummary: Searched %s and found %d queries for %d domain names from %d clients.\n", domainName, lineCount, len(domainMap), len(ipMap))
	fmt.Printf("Query time: %.2f seconds\n", elapsedTime)
	return lineCount
}

func sortMap(mapUnsorted map[string]int) []Count {
	var mapSorted []Count

	for key, value := range mapUnsorted {
		mapSorted = append(mapSorted, Count{key, value})
	}
	sort.Slice(mapSorted, func(k, v int) bool {
		return mapSorted[k].Value > mapSorted[v].Value
	})
	return mapSorted
}

func menu() {
	fmt.Println("\ndnscl Menu:")
	fmt.Println("")
	fmt.Println("Enter 0 to exit")
	fmt.Println("Enter 1 to search ip")
	fmt.Println("Enter 2 to search domain")
}

func main() {
	var choice int

	if len(os.Args) < 2 {
		for {
			menu()
			input := wildcard
			fmt.Print("=> ")
			_, err := fmt.Scanf("%d", &choice)
			if err != nil {
				fmt.Println("Invalid input, try again.")
			} else {
				switch choice {
				case 0:
					os.Exit(0)
				case 1:
					fmt.Print("ip address: ")
					fmt.Scanln(&input)
					dnsclIPaddress(input)
				case 2:
					fmt.Print("domain name: ")
					fmt.Scanln(&input)
					dnsclDomainName(input)
				default:
					fmt.Println("Invalid choice, try again.")
				}
			}
		}
	}
}
