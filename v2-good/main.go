package main

import (
	"fmt"
	v3 "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/kylelemons/godebug/pretty"
	"github.com/orcaman/concurrent-map"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"
)

var zimbraAuthTokens = true
var TimerStarted = false
var CurrentObjectCount = 0

var TargetDNFoundCounter = 0

type LDIFMasterObjectRoster struct {
	server1File         string
	server1FriendlyName string
	server2File         string
	server2FriendlyName string

	//zimbraAuthTokens
	//zimbraCsrfTokenData
	//entryCSN
	SkipFluff bool

	server1DataSet cmap.ConcurrentMap
	server2DataSet cmap.ConcurrentMap
}

var ValidEntryCounter = 0
var server1Entries string

func main() {

	//Each LDAP Object lives in an array and will be done in a foreach.
	//Every LDIFMasterObjectRoster object has 2 server LDIF File names, settings for skipping tokens, and an LDAP data object.
	//The data object in each will be stored for conflict resolution.
	//Each iteration has 2 execution tasks. 1 against 2 and 2 against 1.

	//To configure, build an array of LDIF objects.
	//var MasterRoster []LDIFMasterObjectRoster
	//
	//Now construct the ldap Objects
	//ldapSetCheck1 := LDIFMasterObjectRoster{
	//	server1File:         "FIRST_LDAP_FILENAME_WITH_PATH",
	//	server2File:         "SECOND_LDAP_FILENAME_WITH_PATH",
	//	SkipFluff:           true,
	//	server1FriendlyName: "FIRST_LDAP_FRIENDLY_NAME",
	//	server2FriendlyName: "SECOND_LDAP_FRIENDLY_NAME",
	//	server1DataSet:      cmap.New(),
	//	server2DataSet:      cmap.New(),
	//}
	
	//You MUST add each causal permutation as an object. A delta both ways between the servers will be checked.
	//So if I have Masters holder-ldap-1, holder-ldap-2, holder-ldap-3, then I would create an LDIFMasterObjectRoster for
	//server1 = holder-ldap-1 server2 = holder-ldap-2
	//In the above object, 1 will check 2 and 2 will check 1.

	MasterRoster := SetupServerFiles()
	totalLen := len(MasterRoster) * 2
	counter := 0
	log.Println("Phase 1: Check for orphaned Objects. This phase has " + strconv.Itoa(totalLen) + " stages.")
	for _, v := range MasterRoster {
		counter++
		log.Println("(Phase 1, Stage " + strconv.Itoa(counter) + "/" + strconv.Itoa(totalLen) + ") Comparing LDAP Exports of " + v.server1FriendlyName + " against " + v.server2FriendlyName)
		log.Println("Reading " + v.server1FriendlyName + " into memory")
		b, err := ioutil.ReadFile(`C:\Users\John Holder\Desktop\ldap\` + v.server1File) // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		server1, err := ldif.Parse(string(b), true)
		if err != nil {
			log.Printf("Failed to parse RFC 2849 example: %s", err)
		}

		log.Println("Reading " + v.server2FriendlyName + " into memory")
		b, err = ioutil.ReadFile(`C:\Users\John Holder\Desktop\ldap\` + v.server2File) // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		server2, err := ldif.Parse(string(b), true)
		if err != nil {
			log.Printf("Failed to parse RFC 2849 example: %s", err)
		}
		//var TimerStarted = false
		var wg sync.WaitGroup
		S1Chunks := chunkSlice(server1.AllEntries(), 43435)
		for k, thisLDAPChunk := range S1Chunks {
			fmt.Println("Main: Starting worker", k)
			wg.Add(1)
			go worker(&wg, k, thisLDAPChunk, server2)
		}
		fmt.Println("Main: waiting for comparison between Server " + v.server1FriendlyName + " and " + v.server2FriendlyName + " to complete.")
		wg.Wait()
		fmt.Println("Main: Starting comparison between Server " + v.server2FriendlyName + " and " + v.server1FriendlyName + ".")

		S2Chunks := chunkSlice(server2.AllEntries(), 43435)
		for k, thisLDAPChunk := range S2Chunks {
			fmt.Println("Main: Starting worker", k)
			wg.Add(1)
			go worker(&wg, k, thisLDAPChunk, server1)
		}
		fmt.Println("Main: waiting for comparison between Server " + v.server2FriendlyName + " and " + v.server1FriendlyName + " to complete.")
		wg.Wait()
		fmt.Println("Main: Completed")
	}
	log.Println("Starting Phase 2: Conflict Resolution.")
	fmt.Println("Done")

}
func worker(wg *sync.WaitGroup, id int, S1Object []*v3.Entry, S2Object *ldif.LDIF) {
	defer wg.Done()

	fmt.Printf("Worker %v: Started\n", id)
	CheckForObject(S1Object, S2Object)
	fmt.Printf("Worker %v: Finished\n", id)
}

var IncorrectValuesMap = cmap.New()

func CheckForObject(S1Objects []*v3.Entry, S2Object *ldif.LDIF) (bool, []*v3.EntryAttribute) {

	for _, Server1Object := range S1Objects {
		found, S2Entry := S2Object.GetAttributesByDN(Server1Object.DN)
		if !found {
			fmt.Println("Can't find " + Server1Object.DN + " in Server 2")
			os.Exit(1)
		}
		DidFindAttibute := false
		for _, Server1Attribute := range Server1Object.Attributes {
			ThisAttribute := Server1Attribute.Name
			for _, Server2Attributes := range S2Entry {
				if ThisAttribute != Server2Attributes.Name {
					continue
				}
				DidFindAttibute = true
				if !reflect.DeepEqual(Server1Attribute.Values, Server2Attributes.Values) {
					fmt.Println(ThisAttribute)
					fmt.Println(pretty.Compare(Server1Attribute.Values, Server2Attributes.Values))
					log.Println(Server1Object.DN + " doesn't have the same values as Server 2.")
					log.Println("Did Find Attribute")
					fmt.Println(DidFindAttibute)
				}
			}
		}
	}

	return true, nil
}

func chunkSlice(slice []*v3.Entry, chunkSize int) [][]*v3.Entry {
	var chunks [][]*v3.Entry
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

func bgTask() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		StatusUpdate := "S1 Objects: " + server1Entries + "; S2 Objects:  Entries Validated: " + strconv.Itoa(ValidEntryCounter) + "/" + server1Entries + "      "
		fmt.Printf("\r%s", StatusUpdate)
		//fmt.Println(StatusUpdate)
	}
}
