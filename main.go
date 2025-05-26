package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const shodanAPIKey = "SHODAN_API_HERE"

type Config struct {
	Wordlist     string
	Domain       string
	Concurrency  int
	Output       string
	AutoDiscover bool
}

type ScanResult struct {
	BucketName string   `json:"bucket_name"`
	Findings   []string `json:"findings"`
	URL        string   `json:"url"`
}

type ScanResults struct {
	Results []ScanResult `json:"results"`
	Stats   struct {
		TotalBuckets int `json:"total_buckets"`
		Vulnerable   int `json:"vulnerable_buckets"`
	} `json:"stats"`
}

// Function to check if subdomain is live with status code filtering
func isLiveSubdomain(subdomain string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://" + subdomain)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if status code indicates live domain
	switch resp.StatusCode {
	case 200, 302, 403, 404:
		return true
	default:
		return false
	}
}

func main() {
	ctx := context.Background()
	cfg := parseFlags()

	// Initialize results
	allResults := &ScanResults{}

	// Initialize AWS client
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Printf("Warning: AWS credentials not found, continuing with basic checks: %v", err)
	}
	s3Client := s3.NewFromConfig(awsCfg)

	// Setup progress tracking
	progressInterval := time.Second * 5
	progressTicker := time.NewTicker(progressInterval)
	defer progressTicker.Stop()

	progress := struct {
		sync.Mutex
		current int
	}{current: 0}

	go func() {
		for range progressTicker.C {
			progress.Lock()
			fmt.Printf("\rProgress: %d buckets checked", progress.current)
			progress.Unlock()
		}
	}()

	// Get target buckets
	var buckets []string
	if cfg.AutoDiscover {
		fmt.Println("\nStarting subdomain discovery...")
		subdomains := discoverSubdomains(cfg.Domain)
		fmt.Printf("Found %d subdomains\n", len(subdomains))

		// Discover buckets for main domain and subdomains
		allDomains := append([]string{cfg.Domain}, subdomains...)
		for i, domain := range allDomains {
			fmt.Printf("\n[%d/%d] Checking domain: %s\n", i+1, len(allDomains), domain)
			domainBuckets := discoverBuckets(domain)
			buckets = append(buckets, domainBuckets...)
		}
		fmt.Printf("\nDiscovered %d potential buckets\n", len(buckets))
	} else {
		buckets = readBucketNames(cfg.Wordlist)
		fmt.Printf("Loaded %d buckets from wordlist\n", len(buckets))
	}

	// Deduplicate buckets
	uniqueBuckets := make(map[string]bool)
	for _, bucket := range buckets {
		uniqueBuckets[bucket] = true
	}

	bucketsList := make([]string, 0, len(uniqueBuckets))
	for bucket := range uniqueBuckets {
		bucketsList = append(bucketsList, bucket)
	}
	fmt.Printf("Found %d unique buckets after deduplication\n", len(bucketsList))
	allResults.Stats.TotalBuckets = len(bucketsList)

	// Create result channel
	results := make(chan ScanResult, len(bucketsList))

	// Start worker pool
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, cfg.Concurrency)

	for _, bucket := range bucketsList {
		wg.Add(1)
		go func(bucket string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			// Setup HTTP client with exponential backoff, retries and HTTP/2 support
			transport := &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DisableCompression:    false,
				MaxIdleConnsPerHost:   cfg.Concurrency,
			}

			client := &http.Client{
				Timeout:   10 * time.Second,
				Transport: transport,
			}
			maxRetries := 3
			var resp *http.Response
			var err error

			for retries := 0; retries < maxRetries; retries++ {
				if retries > 0 {
					time.Sleep(time.Duration(retries*2) * time.Second) // Exponential backoff
				}

				req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.s3.amazonaws.com", bucket), nil)
				if err != nil {
					return
				}

				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

				resp, err = client.Do(req)
				if err != nil {
					continue
				}

				if resp.StatusCode == 429 || resp.StatusCode >= 500 {
					resp.Body.Close()
					continue
				}

				break
			}

			if err != nil || resp == nil {
				return
			}
			defer resp.Body.Close()

			var findings []string

			// Check if bucket exists
			if resp.StatusCode != 404 {
				findings = append(findings, "Bucket exists")

				// Check if public
				if resp.StatusCode == 200 {
					findings = append(findings, "Publicly accessible")
				}

				// If AWS credentials available, do deeper checks
				if s3Client != nil {
					// Check ACL
					acl, err := s3Client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
						Bucket: aws.String(bucket),
					})
					if err == nil {
						for _, grant := range acl.Grants {
							if grant.Grantee.URI != nil && *grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" {
								findings = append(findings, fmt.Sprintf("Public %v permission", grant.Permission))
							}
						}
					}

					// Check encryption
					enc, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
						Bucket: aws.String(bucket),
					})
					if err != nil || enc.ServerSideEncryptionConfiguration == nil {
						findings = append(findings, "No default encryption")
					}
				}
			}

			// Update progress counter
			progress.Lock()
			progress.current++
			progress.Unlock()

			if len(findings) > 0 {
				result := ScanResult{
					BucketName: bucket,
					Findings:   findings,
					URL:        fmt.Sprintf("https://%s.s3.amazonaws.com", bucket),
				}
				results <- result
				fmt.Printf("\n[%s] Found: %s", bucket, strings.Join(findings, ", "))
			}

			// Basic rate limiting
			time.Sleep(100 * time.Millisecond)
			fmt.Print("\033[2K") // Clear line
		}(bucket)
	}

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	for result := range results {
		allResults.Results = append(allResults.Results, result)
		if len(result.Findings) > 0 {
			allResults.Stats.Vulnerable++
		}
	}

	// Save results as JSON
	if cfg.Output != "" {
		jsonData, err := json.MarshalIndent(allResults, "", "    ")
		if err != nil {
			log.Fatalf("Failed to encode results as JSON: %v", err)
		}

		// Windows compatible file permissions (0644 in octal)
		if err := os.WriteFile(cfg.Output, jsonData, 0666); err != nil {
			log.Fatalf("Failed to write results file: %v", err)
		}
		fmt.Printf("\nResults saved to %s\n", cfg.Output)
	}

	// Print summary
	fmt.Printf("\nScan Summary:\n")
	fmt.Printf("Total Buckets: %d\n", allResults.Stats.TotalBuckets)
	fmt.Printf("Vulnerable Buckets: %d\n", allResults.Stats.Vulnerable)
}

func parseFlags() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.Wordlist, "wordlist", "", "Path to wordlist file")
	flag.StringVar(&cfg.Domain, "domain", "", "Target domain for automatic discovery")
	flag.IntVar(&cfg.Concurrency, "concurrent", 10, "Number of concurrent scanners")
	flag.StringVar(&cfg.Output, "output", "", "Output file path")
	flag.BoolVar(&cfg.AutoDiscover, "auto-discover", false, "Enable automatic bucket discovery")
	flag.Parse()

	if cfg.AutoDiscover && cfg.Domain == "" {
		log.Fatal("Domain is required when auto-discover is enabled")
	}

	if !cfg.AutoDiscover && cfg.Wordlist == "" {
		log.Fatal("Wordlist is required when not using auto-discovery")
	}

	return cfg
}

func readBucketNames(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open wordlist: %v", err)
	}
	defer file.Close()

	var buckets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		bucket := strings.TrimSpace(scanner.Text())
		if bucket != "" && !strings.HasPrefix(bucket, "#") {
			buckets = append(buckets, bucket)
		}
	}

	return buckets
}

func discoverSubdomains(domain string) []string {
	uniqueSubdomains := make(map[string]bool)

	// Helper function to add subdomains
	addSubdomain := func(subdomain string) {
		subdomain = strings.ToLower(strings.TrimSpace(subdomain))
		if subdomain != "" && subdomain != domain && strings.HasSuffix(subdomain, "."+domain) {
			uniqueSubdomains[subdomain] = true
		}
	}

	// Find subdomains from crt.sh
	crtURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := http.Get(crtURL)
	if err == nil {
		defer resp.Body.Close()
		var results []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&results); err == nil {
			for _, result := range results {
				// Split multiple domains in single record
				for _, name := range strings.Split(result.NameValue, "\n") {
					addSubdomain(name)
				}
			}
		}
	}

	// Find subdomains from Shodan
	shodanURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, shodanAPIKey)
	resp, err = http.Get(shodanURL)
	if err == nil {
		defer resp.Body.Close()
		var result struct {
			Subdomains []string `json:"subdomains"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, subdomain := range result.Subdomains {
				addSubdomain(subdomain + "." + domain)
			}
		}
	}

	// Find subdomains from Google
	searchUrls := []string{
		fmt.Sprintf("https://www.google.com/search?q=site:*.%s -www.%s&num=100", domain, domain),
		fmt.Sprintf("https://www.google.com/search?q=site:%s&num=100", domain),
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, searchUrl := range searchUrls {
		req, err := http.NewRequest("GET", searchUrl, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Extract subdomains from response
		re := regexp.MustCompile(`[a-zA-Z0-9-]+\.` + regexp.QuoteMeta(domain))
		matches := re.FindAllString(string(body), -1)
		for _, match := range matches {
			addSubdomain(match)
		}

		time.Sleep(2 * time.Second) // Avoid rate limiting
	}

	// Try DNS brute force
	commonSubdomains := []string{"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
		"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev",
		"staging", "web", "admin", "proxy", "api", "git", "stats", "server", "mx1", "cdn", "enterprise", "portal",
		"vpn", "mail2", "shop", "api2", "beta", "store"}

	// Async DNS lookups
	type dnsResult struct {
		subdomain string
		exists    bool
	}

	resultChan := make(chan dnsResult, len(commonSubdomains))
	for _, sub := range commonSubdomains {
		go func(sub string) {
			hostname := sub + "." + domain
			_, err := net.LookupHost(hostname)
			resultChan <- dnsResult{
				subdomain: hostname,
				exists:    err == nil,
			}
		}(sub)
	}

	// Collect DNS results
	for range commonSubdomains {
		result := <-resultChan
		if result.exists {
			addSubdomain(result.subdomain)
		}
	}

	// Convert map to slice and check if domains are live
	var subdomains []string
	ch := make(chan string, len(uniqueSubdomains))
	var wg sync.WaitGroup

	// Check domains concurrently
	for subdomain := range uniqueSubdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			if isLiveSubdomain(sub) {
				ch <- sub
			}
		}(subdomain)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect results
	for subdomain := range ch {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}

func discoverBuckets(domain string) []string {
	// Initialize buckets and tracking map
	var buckets []string
	uniqueBuckets := make(map[string]bool)

	// Add bucket helper function
	addBucket := func(bucket string) {
		if !uniqueBuckets[bucket] {
			uniqueBuckets[bucket] = true
			buckets = append(buckets, bucket)
		}
	}

	companyName := strings.Split(domain, ".")[0]

	// Company name variations
	parts := strings.Split(companyName, "-")
	variations := []string{
		companyName,
		strings.ReplaceAll(companyName, "-", ""),
		strings.ReplaceAll(companyName, ".", ""),
	}

	// Add common company suffixes/prefixes
	commonAffixes := []string{"inc", "llc", "corp", "ltd", "group", "tech", "cloud", "app", "apps"}
	for _, affix := range commonAffixes {
		variations = append(variations,
			fmt.Sprintf("%s-%s", companyName, affix),
			fmt.Sprintf("%s%s", companyName, affix),
			fmt.Sprintf("%s-%s", affix, companyName),
			fmt.Sprintf("%s%s", affix, companyName),
		)
	}

	// Add variations from parts
	if len(parts) > 1 {
		variations = append(variations,
			strings.Join(parts, ""),
			parts[0],
			parts[len(parts)-1],
		)
	}

	// Environment variations
	envs := []string{"prod", "dev", "staging", "qa", "test", "uat", "production", "development"}
	regions := []string{"us", "eu", "ap", "sa", "ca", "me", "af"}

	// Common bucket patterns
	patterns := []string{
		"%s",          // company
		"%s-storage",  // company-storage
		"%s-backup",   // company-backup
		"backup-%s",   // backup-company
		"%s-data",     // company-data
		"data-%s",     // data-company
		"%s-assets",   // company-assets
		"assets-%s",   // assets-company
		"%s-media",    // company-media
		"media-%s",    // media-company
		"%s-static",   // company-static
		"static-%s",   // static-company
		"%s-files",    // company-files
		"files-%s",    // files-company
		"%s-uploads",  // company-uploads
		"uploads-%s",  // uploads-company
		"%s-logs",     // company-logs
		"logs-%s",     // logs-company
		"%s-images",   // company-images
		"images-%s",   // images-company
		"%s-web",      // company-web
		"web-%s",      // web-company
		"%s-public",   // company-public
		"public-%s",   // public-company
		"%s-private",  // company-private
		"private-%s",  // private-company
		"%s-internal", // company-internal
		"internal-%s", // internal-company
	}

	// Generate variations
	for _, name := range variations {
		// Use domain parts for better matches
		domainParts := strings.Split(domain, ".")
		if len(domainParts) > 1 {
			variations = append(variations,
				strings.Join(domainParts[:len(domainParts)-1], ""),
				strings.Join(domainParts[:len(domainParts)-1], "-"),
			)
		}

		// Base patterns
		for _, pattern := range patterns {
			addBucket(fmt.Sprintf(pattern, name))

			// With environments
			for _, env := range envs {
				addBucket(fmt.Sprintf(pattern+"-"+env, name))
				addBucket(fmt.Sprintf(env+"-"+pattern, name))
			}

			// With regions
			for _, region := range regions {
				addBucket(fmt.Sprintf(pattern+"-"+region, name))
				addBucket(fmt.Sprintf(region+"-"+pattern, name))
			}
		}
	}

	// AWS specific formats with regions
	awsRegions := []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-west-3",
		"eu-central-1",
		"ap-southeast-1", "ap-southeast-2",
		"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
		"ap-south-1",
		"sa-east-1",
		"ca-central-1",
	}

	awsFormats := []string{
		"%s.s3.amazonaws.com",
		"%s.s3.%s.amazonaws.com",         // with region
		"%s.s3-website.%s.amazonaws.com", // website endpoint
		"%s-s3",
		"s3-%s",
		"%s.s3-website-%s.amazonaws.com", // alt website endpoint
	}

	for _, name := range variations {
		for _, format := range awsFormats {
			if strings.Contains(format, "%s.%s") {
				// Format with region
				for _, region := range awsRegions {
					addBucket(fmt.Sprintf(format, name, region))
				}
			} else {
				addBucket(fmt.Sprintf(format, name))
			}
		}
	}

	// Try common AWS account formats
	accountFormats := []string{
		"%s-aws",
		"aws-%s",
		"%s-amazon",
		"amazon-%s",
	}

	for _, name := range variations {
		for _, format := range accountFormats {
			addBucket(fmt.Sprintf(format, name))
		}
	}

	// Add domain-based formats
	domainFormats := []string{
		"",     // domain as is
		"www-", // www prefix
		"%s-backup",
		"backup-%s",
		"%s-static",
		"static-%s",
		"%s-assets",
		"assets-%s",
	}

	for _, format := range domainFormats {
		if format == "" {
			addBucket(domain)
		} else {
			addBucket(fmt.Sprintf(format, domain))
		}
	}

	// Try to find more buckets from Google dorks
	searchUrls := []string{
		fmt.Sprintf("https://www.google.com/search?q=site:s3.amazonaws.com+%s", domain),
		fmt.Sprintf("https://www.google.com/search?q=site:*.s3.amazonaws.com+%s", domain),
	}

	// Search for bucket patterns in Google results
	client := &http.Client{Timeout: 10 * time.Second}
	for _, searchUrl := range searchUrls {
		req, err := http.NewRequest("GET", searchUrl, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Look for bucket patterns in response
		bucketPatterns := []string{
			`[\w-]+\.s3\.amazonaws\.com`,
			`s3\.[\w-]+\.amazonaws\.com/[\w-]+`,
			`[\w-]+\.s3-[\w-]+\.amazonaws\.com`,
		}

		for _, pattern := range bucketPatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllString(string(body), -1)
			for _, match := range matches {
				addBucket(strings.Split(match, "/")[0]) // Get just the bucket name
			}
		}
	}

	fmt.Println("\nGoogle dorks for manual checking:")
	fmt.Printf("site:s3.amazonaws.com \"%s\"\n", domain)
	fmt.Printf("site:*.s3.amazonaws.com \"%s\"\n", domain)
	fmt.Printf("site:s3-external-1.amazonaws.com \"%s\"\n", domain)
	fmt.Printf("site:s3.dualstack.us-east-1.amazonaws.com \"%s\"\n", domain)
	fmt.Printf("site:amazonaws.com inurl:s3.amazonaws.com \"%s\"\n", domain)
	fmt.Printf("site:s3.amazonaws.com intitle:\"index of\" \"%s\"\n", domain)
	fmt.Printf("site:s3.amazonaws.com inurl:\".s3.amazonaws.com/\" \"%s\"\n", domain)
	fmt.Printf("site:s3.amazonaws.com intitle:\"index of\" \"bucket\" \"%s\"\n", domain)
	fmt.Printf("(site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com OR site:*.s3.dualstack.us-east-1.amazonaws.com OR site:*.s3.ap-south-1.amazonaws.com) \"%s\"\n", domain)

	return buckets
}
