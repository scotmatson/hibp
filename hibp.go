package main

import (
	"encoding/csv"
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
			pwned++
			time.Sleep(1500 * time.Millisecond)
		}
	}
	fmt.Printf("Accounts Checked: %d\n", checked)
	fmt.Printf("Accounts Pwned: %d", pwned)
}

func checkBreachedAccount(key, service, account string) []byte {
	// TODO { "statusCode": 429, "message": "Rate limit is exceeded. Try again in 30 seconds." }
	apiUrl := "https://haveibeenpwned.com/api/v3/{service}/{account}"
	apiUrl = strings.Replace(apiUrl, "{service}", service, 1)
	apiUrl = strings.Replace(apiUrl, "{account}", url.QueryEscape(account), 1)
	client := &http.Client{}

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("hibp-api-key", key)
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	b, err := ioutil.ReadAll(res.Body) // Not memory efficient
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	return b
}

/*
func hash_checker() () {
	apiUrl := "GET https://api.pwnedpasswords.com/range/{first 5 hash chars}"
}
*/

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
			s := string(b)
			fmt.Println(s)
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
			s := string(b)
			fmt.Println(s)
		} else {
			checkBreachedAccountsFile(*key, service, *filename)
		}

	case "password":
		fmt.Println("Not yet implemented.")
	default:
		fmt.Println("This will output a help menu.")
	}
}
