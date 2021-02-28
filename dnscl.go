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
	"sort"
	"strings"
	"time"
)

const (
	filename = "/var/log/syslog" // path to syslog file
	// filename = "/var/log/messages" // path to alternate syslog file
	wildcard = ""
)

type pair struct {
	Key   string
	Value int
}

type pairList []pair

func (pair pairList) Len() int {
	return len(pair)
}

func (pair pairList) Swap(p, q int) {
	pair[p], pair[q] = pair[q], pair[p]
}

func (pair pairList) Less(p, q int) bool {
	return pair[p].Value < pair[q].Value
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

func sortMap(mapUnsorted map[string]int) pairList {
	pairListSorted := make(pairList, len(mapUnsorted))
	index := 0
	for key, value := range mapUnsorted {
		pairListSorted[index] = pair{key, value}
		index++
	}
	sort.Sort(sort.Reverse(pairListSorted))
	return pairListSorted
}

func main() {
	var ipAddr string

	if len(os.Args) == 2 {
		ipAddr = os.Args[1]
	} else {
		ipAddr = wildcard
	}

	fmt.Println("Welcome to the Go version of dnscl!")
	dnsclIPaddress(ipAddr)

}
