package main

import (
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func arePasswordsLeaked(key, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	r := csv.NewReader(file)

	var checked int
	var pwned int
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		passwordHash := convertToSha1String(record[0])
		leaked := isPasswordLeaked(key, passwordHash)
		checked++
		if leaked {
			fmt.Printf("%v: %v %v", checked, record[0], "has been leaked!!!\n")
			pwned++
		}
	}
	fmt.Printf("Passwords Checked: %d\n", checked)
	fmt.Printf("Passwords Leaked: %d", pwned)
}

func checkBreachedAccountsFile(key, service, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	r := csv.NewReader(file)

	var checked int
	var pwned int
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		b := checkBreachedAccount(key, service, record[0])
		checked++
		if len(b) > 0 {
			fmt.Printf("%d: %s - %s\n", checked, record[0], b)
			pwned++
		} else {
			fmt.Printf("%d: %s - []\n", checked, record[0])
		}
		time.Sleep(1500 * time.Millisecond)
	}
	fmt.Printf("Accounts Checked: %d\n", checked)
	fmt.Printf("Accounts Pwned: %d", pwned)
}

// Requests to the breaches and pastes APIs are limited to one per every 1500 milliseconds
func checkBreachedAccount(key, service, account string) []byte {
	apiUrl := "https://haveibeenpwned.com/api/v3/{service}/{account}"
	apiUrl = strings.Replace(apiUrl, "{service}", service, 1)
	apiUrl = strings.Replace(apiUrl, "{account}", url.QueryEscape(account), 1)

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{}
	req.Header.Add("hibp-api-key", key)

	var res http.Response
	var b []byte
	for ok := true; ok; ok = !ok {
		res, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer res.Body.Close()

		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}

		// { "statusCode": 429, "message": "Rate limit is exceeded. Try again in 30 seconds." }
		if res.StatusCode == 429 {
			log.Printf("%s\n", b)
			fmt.Print("Sleeping for 30 seconds...")
			time.Sleep(30 * time.Second)
			fmt.Println("retrying")
			ok = false
		}
	}

	// { "statusCode": 401, "message": "Access denied due to invalid hibp-api-key." }
	if res.StatusCode == 401 {
		log.Fatalf("%s\n", b)
	}

	return b
}

// Convert a String into a sha1 hash String.
func convertToSha1String(s string) string {
	bs := []byte(s)
	sha1Bytes := sha1.Sum(bs)
	return hex.EncodeToString(sha1Bytes[:])
}

// There is no rate limit on the Pwned Passwords API.
func isPasswordLeaked(key, passwordHash string) bool {
	apiUrl := "https://api.pwnedpasswords.com/range/{first 5 hash chars}"
	apiUrl = strings.Replace(apiUrl, "{first 5 hash chars}", passwordHash[:5], 1)

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("hibp-api-key", key)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	b, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	return strings.Contains(
		strings.ToLower(string(b)),
		strings.ToLower(passwordHash[5:]),
	)
}

func main() {
	fmt.Println("*-----------------------*")
	fmt.Println("??? Have I Been Pwned ???")
	fmt.Println("*-----------------------*")

	key := flag.String("k", "", "HIBP API Key")
	service := flag.String("s", "", "HIBP Service")
	filename := flag.String("f", "", "List to check")
	flag.Parse()

	switch *service {
	case "breach":
		service := "breachedaccount"
		if *filename == "" {
			if (len(flag.Args())) < 1 {
				log.Fatal("No account given.")
			}
			b := checkBreachedAccount(*key, service, flag.Args()[0])
			fmt.Printf("%s", b)
		} else {
			checkBreachedAccountsFile(*key, service, *filename)
		}
	case "paste":
		service := "pasteaccount"
		if *filename == "" {
			if (len(flag.Args())) < 1 {
				log.Fatal("No account given.")
			}
			b := checkBreachedAccount(*key, service, flag.Args()[0])
			fmt.Printf("%s", b)
		} else {
			checkBreachedAccountsFile(*key, service, *filename)
		}
	case "password":
		if *filename == "" {
			if (len(flag.Args())) < 1 {
				log.Fatal("No account given.")
			}
			passwordHash := convertToSha1String(flag.Args()[0])
			leaked := isPasswordLeaked(*key, passwordHash)
			if leaked {
				fmt.Println(passwordHash, "has been leaked.")
			}
		} else {
			arePasswordsLeaked(*key, *filename)
		}
	default:
		fmt.Println("This will output a help menu.")
	}
}
