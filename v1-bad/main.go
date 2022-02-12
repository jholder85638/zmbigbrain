package main

import (
	"bufio"
	"fmt"
	"github.com/orcaman/concurrent-map"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var zimbraAuthTokens = true
var TimerStarted = false
var CurrentObjectCount = 0

var TargetDNFoundCounter = 0

type LDIFMasterObjectRoster struct {
	server1 string
	server2 string

	//zimbraAuthTokens
	checkAuthToken bool

	//zimbraCsrfTokenData
	checkCSRFToken bool

	server1DataSet cmap.ConcurrentMap
	server2DataSet cmap.ConcurrentMap
}

func main() {

	//Each LDAP Object lives in an array and will be done in a foreach.
	//Every LDIFMasterObjectRoster object has 2 server LDIF File names, settings for skipping tokens, and an LDAP data object.
	//The data object in each will be stored for conflict resolution.
	//Each iteration has 2 execution tasks. 1 against 2 and 2 against 1.
	var MasterRoster []LDIFMasterObjectRoster
	ldapSetCheck1 := LDIFMasterObjectRoster{server1: "ldap1.bak", server2: "ldap3.bak", checkAuthToken: false, checkCSRFToken: false, server1DataSet: cmap.New(), server2DataSet: cmap.New()}
	MasterRoster = append(MasterRoster, ldapSetCheck1)
	ldapSetCheck2 := LDIFMasterObjectRoster{server1: "ldap2.bak", server2: "ldap1.bak", checkAuthToken: false, checkCSRFToken: false, server1DataSet: cmap.New(), server2DataSet: cmap.New()}
	MasterRoster = append(MasterRoster, ldapSetCheck2)
	ldapSetCheck3 := LDIFMasterObjectRoster{server1: "ldap3.bak", server2: "ldap1.bak", checkAuthToken: false, checkCSRFToken: false, server1DataSet: cmap.New(), server2DataSet: cmap.New()}
	MasterRoster = append(MasterRoster, ldapSetCheck3)

	totalLen := len(MasterRoster) * 2
	counter := 0
	log.Println("Phase 1: Check for orphaned Objects. This phase has " + strconv.Itoa(totalLen) + " stages.")
	for _, v := range MasterRoster {

		counter++
		log.Println("(Phase 1, Stage " + strconv.Itoa(counter) + "/" + strconv.Itoa(totalLen) + ") Comparing LDAP Exports of " + v.server1 + " against " + v.server2)
		SourceFileReader(v.server1, v.server2, v.server1DataSet)

		counter++
		log.Println("(Phase 1, Stage " + strconv.Itoa(counter) + "/" + strconv.Itoa(totalLen) + ") Comparing LDAP Exports of " + v.server2 + " against " + v.server1)
		log.Println("Comparing LDAP Exports of " + v.server2 + " against " + v.server1)
		SourceFileReader(v.server2, v.server1, v.server2DataSet)
	}
	log.Println("Starting Phase 2: Conflict Resolution.")
	fmt.Println("Done")
}

func bgTask() {
	ticker := time.NewTicker(1 * time.Second)
	for _ = range ticker.C {
		StatusUpdate := "DN Objects committed to memory: " + strconv.Itoa(CurrentObjectCount) + " Found " + strconv.Itoa(TargetDNFoundCounter) + " objects in target.                "
		fmt.Printf("\r%s", StatusUpdate)
		//fmt.Println(StatusUpdate)
	}
}

//func CompareLDIF(compareFrom string, compareTo string) {
//	SourceFileReader(compareFrom, compareTo)
//}

func SourceFileReader(thisFile string, lookingForFile string, dataMap cmap.ConcurrentMap) {

	file, err := os.Open(`C:\Users\John Holder\Desktop\ldap\` + thisFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCounter := 0
	SourceDNBlockStringBuilder := ""
	CurrentDN := ""
	foundSourceDNBlock := false
	for scanner.Scan() {
		lineCounter++
		CurrentObjectCount = dataMap.Count()
		if !TimerStarted {
			go bgTask()
			TimerStarted = true
		}
		if zimbraAuthTokens {
			if strings.Contains(scanner.Text(), "zimbraAuthTokens:") {
				continue
			}
		}

		if foundSourceDNBlock {

			//If we have a blank line, that means that this is the end of the LDIF block.
			if scanner.Text() == "" {

				//Check for the object in memory.
				if tmp, ok := dataMap.Get(CurrentDN); ok {
					//If the object is already in memory, somehow we have duplicate DNs
					log.Println("Object: " + CurrentDN + " already exists! This shouldn't happen.")
					log.Println("Tried to put: " + CurrentDN)
					log.Println("But found this in memory: " + tmp.(string))
					log.Panic(tmp)
				} else {

					//We've finished DN scanning (foundSourceDNBlock is true) but the current line is blank.
					//This means we're at the end of this DN block
					//It's time to commit the DN block to memory.
					dataMap.Set(CurrentDN, SourceDNBlockStringBuilder)

					//now that this is done, we need to clear the variables and proceed to the next block.

					//Now we need to scan the Target LDIF file for this DN.
					found, _, _ := ComparelineReader(lookingForFile, CurrentDN)
					if !found {
						log.Println("Could not find the Requested DN in the target file. DN: " + CurrentDN + " which is on line: " + strconv.Itoa(lineCounter))
						panic("Write this section.")
					} else {
						TargetDNFoundCounter++
						CurrentDN = ""
						SourceDNBlockStringBuilder = ""
						foundSourceDNBlock = false
					}
				}

			} else {
				//Append the DN Block
				SourceDNBlockStringBuilder += scanner.Text() + "\n"
			}
			//We have a true foundSourceDNBlock, so keep going. Don't mess up this block.
			continue
		}

		//If we're here, that means that foundSourceDNBlock is false.
		//Ideally, we should always have a DN here. If we don't, panic.
		if strings.Contains(scanner.Text(), "dn:") {
			//counter := strings.Split(scanner.Text(), " ")
			CurrentDN = scanner.Text()
			foundSourceDNBlock = true
			SourceDNBlockStringBuilder += scanner.Text() + "\n"
			continue
		} else {
			log.Println(scanner.Text())
			panic("We do not have a DN. We should not be here. There is probably something wrong with the LDIF.")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	StatusUpdate := "DN Objects committed to memory: " + strconv.Itoa(CurrentObjectCount) + " Found " + strconv.Itoa(TargetDNFoundCounter) + " objects in target.                "
	//fmt.Println(StatusUpdate)
	fmt.Println(StatusUpdate)
}

func ComparelineReader(filename string, lookingForDN string) (bool, string, string) {
	//log.Println("Starting to look in " + filename + " for DN: " + lookingForDN)
	file, err := os.Open(`C:\Users\John Holder\Desktop\ldap\` + filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCounter := 0
	CurrentDN := ""
	foundTargetDNBlock := false
	for scanner.Scan() {
		lineCounter++
		if zimbraAuthTokens {
			if strings.Contains(scanner.Text(), "zimbraAuthTokens:") {
				continue
			}
		}
		if foundTargetDNBlock {
			if scanner.Text() == "" {
				//log.Println("true")
				//log.Println("line: " + strconv.Itoa(lineCounter))
				//log.Println(CurrentDN)
				//os.Exit(1)
				//log.Panic(true, strconv.Itoa(lineCounter), CurrentDN)
				return true, strconv.Itoa(lineCounter), CurrentDN
			} else {
				CurrentDN += scanner.Text() + "\n"
			}
			continue
		}
		if scanner.Text() == lookingForDN {
			foundTargetDNBlock = true
			CurrentDN = scanner.Text() + "\n"
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return false, "", ""
}
