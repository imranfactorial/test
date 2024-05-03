package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"golang.org/x/net/html"
	"bufio"
	"flag"
	"os"
	"github.com/fatih/color"
	"github.com/chromedp/chromedp"
	"context"
	"time"
	"github.com/chromedp/cdproto/dom"
	"bytes"
	"log"
	"io/ioutil"
)

var (
	Infolabel = color.New(color.FgBlue).SprintFunc()("[INFO]")
	Warnlabel = color.New(color.FgYellow).SprintFunc()("[WARN]")
	Errlabel  = color.New(color.FgRed).SprintFunc()("[ERROR]")
	flabel   = color.New(color.FgRed).SprintFunc()("]")
	blabel   = color.New(color.FgRed).SprintFunc()("[")
	PWNlabel  = blabel+color.New(color.FgWhite).SprintFunc()("PWND")+flabel
	Discordwebhook = "https://discord.com/api/webhooks/1225711318410199041/iNghI-dVRwIFHHpK333ItgfSEPUNbIBXYWJHwwRME3WcJuR2bD6NhelyZVUHtc5eWnql"
)

func main() {
	fmt.Println(`
 ___ _ _      _    
| _ ) (_)_ _ | |__ 
| _ \ | | ' \| / / 
|___/_|_|_||_|_\_\ 
	Broken Link Scanner		   
	`)
	var (
		url	  string
		list string
		template string
		mode string
	)
	flag.StringVar(&url, "u", "", "URL to scan")
	flag.StringVar(&list, "l", "", "List of URLs to scan")
	flag.StringVar(&template, "t", "", "Scan Template")
	flag.StringVar(&mode, "m", "", "onetime or infinite")
	flag.Parse()
	if url != "" {
		if mode == "onetime" {
			if template != "" {
				fmt.Println(Infolabel, "Scanning", color.New(color.FgCyan).SprintFunc()(url), "for Broken Link Takeover")
				TemplateScan(template, url)
				fmt.Println(Infolabel, "Scan Completed for", color.New(color.FgCyan).SprintFunc()(url))
			} else {
				fmt.Println(Warnlabel, "Template file not provided")
				fmt.Println(Infolabel, "Using Builtin Templates")
				BuiltinChecks(url)
			}
		} else if mode == "infinite" {
			if template != "" {
				for {
					fmt.Println(Infolabel, "Scanning", color.New(color.FgCyan).SprintFunc()(url), "for Broken Link Takeover")
					TemplateScan(template, url)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			} else {
				fmt.Println(Warnlabel, "Template file not provided")
				for {
					fmt.Println(Infolabel, "Using Builtin Templates")
					BuiltinChecks(url)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			}
		} else {
			if template != "" {
				for {
					fmt.Println(Infolabel, "Scanning", color.New(color.FgCyan).SprintFunc()(url), "for Broken Link Takeover")
					TemplateScan(template, url)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			} else {
				fmt.Println(Warnlabel, "Template file not provided")
				for {
					fmt.Println(Infolabel, "Using Builtin Templates")
					BuiltinChecks(url)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			}

		}
	} else if list != "" {
		if mode == "onetime" {
			if template != "" {
				listscan(list, template)
				fmt.Println(Infolabel, "Scan Completed for", color.New(color.FgCyan).SprintFunc()(list))
			} else {
				fmt.Println(Warnlabel, "Template file not provided")
				fmt.Println(Infolabel, "Using Builtin Templates")
				BuiltinChecks(url)
			}
		} else if mode == "infinite" {
			if template != "" {
				for {
					listscan(list, template)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			} else {
				fmt.Println(Warnlabel, "Template file not provided")
				for {
					fmt.Println(Infolabel, "Using Builtin Templates")
					listscanbuiltin(list)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			}
		} else {
			if template != "" {
				for {
					listscan(list, template)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			} else {
				fmt.Println(Warnlabel, "Template file not provided")
				for {
					fmt.Println(Infolabel, "Using Builtin Templates")
					listscanbuiltin(list)
					fmt.Println(Infolabel, "Sleeping for 24 hours")
					time.Sleep(86400 * time.Second)
				}
			}
		}
	} else {
		fmt.Println(Warnlabel, "URL or List not provided")
		flag.PrintDefaults()
		os.Exit(1)
	}


}

func listscan(list, template string){
	
	file, err := os.Open(list)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := scanner.Text()
		fmt.Println(Infolabel, "Scanning", color.New(color.FgCyan).SprintFunc()(url), "for Broken Link Takeover")
		TemplateScan(template, url)
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}
}
func listscanbuiltin(list string){
	
	file, err := os.Open(list)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := scanner.Text()
		fmt.Println(Infolabel, "Scanning", color.New(color.FgCyan).SprintFunc()(url), "for Broken Link Takeover")
		BuiltinChecks(url)
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}
}


func TemplateScan(filename, url string) {
	file, err := os.Open(filename)
	filelines := []string{}
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		filelines = append(filelines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}
	fmt.Println(Infolabel, "Loaded", len(filelines), "Template from", filename)
	platformLinks := ExtractPlatformLinks(url)
	fmt.Println(Infolabel, "Extracted", len(platformLinks), "Platform Links from", color.New(color.FgCyan).SprintFunc()(url))
	for _ , line := range filelines {
		platform, matcher := strings.Split(line, ":")[0], strings.Split(line, ":")[1]
		fmt.Println(Infolabel, "Loaded", color.New(color.FgYellow).SprintFunc()(platform), "Platform Template")
		listlink := getPlatformLinks(platform)
		if listlink == nil {
			fmt.Println(Warnlabel, "Platform", color.New(color.FgYellow).SprintFunc()(platform), "not found in the template")
			continue
		}
		filteredLinks := filterLinks(platformLinks, listlink)
		if len(filteredLinks) == 0 {
			fmt.Println(Warnlabel, "No", platform, "Links found in", color.New(color.FgCyan).SprintFunc()(url))
			continue
		}
		fmt.Println(Infolabel, "Found", len(filteredLinks), platform, "Links in", color.New(color.FgCyan).SprintFunc()(url))
		for _, link := range filteredLinks {
			html, err := HeadlessCrawl(link)
			if err != nil {
				fmt.Println(Warnlabel, "Error while crawling", link, ":", err)
				continue
			}
			if strings.Contains(html, matcher) {
				fmt.Println(PWNlabel, "Broken Link Takeover found for", color.New(color.FgRed).SprintFunc()(link), "from", color.New(color.FgCyan).SprintFunc()(url))
				Webhook("Broken Link Takeover found for "+link+" from "+url)
			}


		}
}
}

func Webhook(data string) {
	jsonStr := []byte(`{"content":"` + data + `"}`)
	req, err := http.NewRequest("POST", Discordwebhook, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

}

func HeadlessCrawl(url string) (string, error) {
	ctx, cancel := chromedp.NewContext(
		context.Background(),
	)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2000*time.Millisecond),
		chromedp.ActionFunc(func(ctx context.Context) error {
			rootNode, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			html, err = dom.GetOuterHTML().WithNodeID(rootNode.NodeID).Do(ctx)
			return err
		}),
	)
	if err != nil {
		return "", fmt.Errorf(Warnlabel, "error while performing the automation logic: %v", err)
	}

	return html, nil
}

func getPlatformLinks(platform string) []string {
	templateData := map[string][]string{
		"Facebook":  {"fb.com", "facebook.com"},
		"Twitter":   {"twitter.com", "t.co", "x.com"},
		"Instagram": {"instagram.com", "instagr.am"},
		"Tiktok":    {"tiktok.com"},
		"Youtube":   {"youtube.com"},
		"Linkedin":  {"linkedin.com"},
		"Telegram":  {"telegram.org","t.me","telegram.me"},
		"Github":    {"github.com"},
		"Gitlab":    {"gitlab.com"},
	}

	if links, ok := templateData[platform]; ok {
		return links
	}
	return nil
}

func filterLinks(links []string, domains []string) []string {
	var filteredLinks []string
	for _, link := range links {
		for _, domain := range domains {
			if strings.Contains(link, domain) {
				filteredLinks = append(filteredLinks, link)
				break
			}
		}
	}
	return filteredLinks
}


func ExtractPlatformLinks(url string) []string {
	httpLinks, err := extractHttpLinks(url)
	if err != nil {
		fmt.Println("[WARN] Error extracting Platform links from", url, ":", err)
		return nil
	}
	platforms := []string{"fb.com", "facebook.com", "twitter.com", "x.com", "tiktok.com", "youtube.com", "linkedin.com", "telegram.org","t.me","github.com","telegram.me","instagr.am","instagram.com"}
	var platformLinks []string
	for _, link := range httpLinks {
		for _, platform := range platforms {
			if strings.Contains(link, platform) {
				platformLinks = append(platformLinks, link)
				break 
			}
		}
	}
	return platformLinks
}



func sendHTTPRequest(url string) (*http.Response, error) {
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36"
	acceptHeader := "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", acceptHeader)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func extractHttpLinks(url string) ([]string, error) {
	var httpLinks []string
	resp, err := sendHTTPRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[WARN] Server Responded with %s", resp.Status)
	}
	links := extractLinks(resp.Body, url)
	for _, link := range links {
		if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
			httpLinks = append(httpLinks, link)
		}
	}
	return httpLinks, nil
}

func extractLinks(body io.Reader, baseURL string) []string {
	var links []string
	z := html.NewTokenizer(body)
	for {
		tt := z.Next()
		switch {
		case tt == html.ErrorToken:
			return links
		case tt == html.StartTagToken:
			token := z.Token()
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						links = append(links, attr.Val)
					}
				}
			}
		}
	}
}


// Last Update - A.Rahman Maheer (Custom Checks Function) 4 APRIL 2024

func BuiltinChecks(url string) {
	fmt.Println(Infolabel, "Loaded 7 Built-in Scanner")
	socialurls := ExtractPlatformLinks(url)
	fmt.Println(Infolabel, "Extracted", len(socialurls), "Platform Links from", color.New(color.FgCyan).SprintFunc()(url))
	fmt.Println(Infolabel, "Checking for BrokenLinks")
	for _, link := range socialurls {
		if strings.Contains(link, "github.com") {
			if checkGitHubURL(url) {
				continue
			} else {
				fmt.Println(PWNlabel, "Broken Link Takeover found for", color.New(color.FgRed).SprintFunc()(link), "from", color.New(color.FgCyan).SprintFunc()(url))
				Webhook("Broken Link Takeover found for " + link + " from " + url)
			}
		} else if strings.Contains(link, "gitlab.com") {
			if checkGitlabURL(url) {
				continue
			} else {
				fmt.Println(PWNlabel, "Broken Link Takeover found for", color.New(color.FgRed).SprintFunc()(link), "from", color.New(color.FgCyan).SprintFunc()(url))
				Webhook("Broken Link Takeover found for " + link + " from " + url)
			}
		} else if strings.Contains(link, "tiktok.com") {
			exists, err := checkTikTok(url)
			if err != nil {
				fmt.Println("Error checking TikTok URL:", err)
				return
			}
			if !exists {
				fmt.Println(PWNlabel, "TikTok account not found for", color.New(color.FgRed).SprintFunc()(link), "from", color.New(color.FgCyan).SprintFunc()(url))
				Webhook("TikTok account not found for " + link + " from " + url)
			}
		} else if strings.Contains(link, "instagram.com") {
			username := strings.Split(link, "/")[3]
			exists, err := instacheck(username)
			if err != nil {
				fmt.Println("Error checking Instagram URL:", err)
				return
			}
			if !exists {
				fmt.Println(PWNlabel, "Instagram account not found for", color.New(color.FgRed).SprintFunc()(link), "from", color.New(color.FgCyan).SprintFunc()(url))
				Webhook("Instagram account not found for " + link + " from " + url)
			}
		} else if strings.Contains(link, "twitter.com") {
			exists, err := twittercheck(link)
			if err != nil {
				fmt.Println("Error checking Twitter URL:", err)
				return
			}
			if !exists {
				fmt.Println(PWNlabel, "Twitter account not found for", color.New(color.FgRed).SprintFunc()(link), "from", color.New(color.FgCyan).SprintFunc()(url))
				Webhook("Twitter account not found for " + link + " from " + url)
			}
		} else if strings.Contains(link, "facebook.com") {
			username := strings.Split(link, "/")[3]
			exists := facebookDetector(username)
			if !exists {
				fmt.Println(PWNlabel, "Facebook account not found for", color.New(color.FgRed).SprintFunc()(link), "from", color.New(color.FgCyan).SprintFunc()(url))
				Webhook("Facebook account not found for " + link + " from " + url)
			}
		}
	}

}

func checkGitHubURL(url string) bool {
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	respCode := response.StatusCode
	if respCode == 200 {
		return true
	}
	return false
}
func checkGitlabURL(url string) bool {
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	respCode := response.StatusCode
	if respCode == 200 {
		return true
	}
	return false
}

func checkTikTok(url string) (bool, error) {
	body, err := HeadlessCrawl(url)
	if err != nil {
		return false, err
	}

	if string(body) != "" {
		if strings.Contains(string(body), `content="Couldn’t find this account`) {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

func instacheck(username string) (bool, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.instagram.com/api/v1/users/web_profile_info/?username=%s", username), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("dpr", "2.625")
	req.Header.Set("referer", fmt.Sprintf("https://www.instagram.com/%s/", username))
	req.Header.Set("sec-ch-prefers-color-scheme", "light")
	req.Header.Set("sec-ch-ua", "\"Google Chrome\";v=\"123\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"123\"")
	req.Header.Set("sec-ch-ua-full-version-list", "\"Google Chrome\";v=\"123.0.6312.123\", \"Not:A-Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"123.0.6312.123\"")
	req.Header.Set("sec-ch-ua-mobile", "?1")
	req.Header.Set("sec-ch-ua-model", "\"Pixel 5\"")
	req.Header.Set("sec-ch-ua-platform", "\"Android\"")
	req.Header.Set("sec-ch-ua-platform-version", "\"13\"")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("user-agent", "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36")
	req.Header.Set("x-asbd-id", "129477")
	req.Header.Set("x-csrftoken", "S0yecfNeZYiY2ex1i8G1x5jsbrWsXm99")
	req.Header.Set("x-ig-app-id", "1217981644879628")
	req.Header.Set("x-ig-www-claim", "0")
	req.Header.Set("x-requested-with", "XMLHttpRequest")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if string(body) != "" {
		if strings.Contains(string(body), "The link you followed may be broken, or the page may have been removed") {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

func twittercheck(url string) (bool, error) {
	response, err := HeadlessCrawl(url)
	if err != nil {
		return false, err
	}
	if response != "" {
		if strings.Contains(response, "This account doesn’t exist") {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

func facebookDetector(username string) bool {
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()
    var res string
    var formID string
    tasks := chromedp.Tasks{
        chromedp.Navigate(`https://mbasic.facebook.com/login/identify/?ctx=recover&search_attempts=0&alternate_search=0&toggle_search_mode=0`),
        chromedp.SendKeys(`#identify_search_text_input`, username),
        chromedp.Submit(`#identify_search_text_input`),
        chromedp.Sleep(2 * time.Second), 
        chromedp.OuterHTML(`html`, &res),
        chromedp.AttributeValue(`form`, "id", &formID, nil, chromedp.ByQuery),
    }
    if err := chromedp.Run(ctx, tasks); err != nil {
        log.Fatal(err)
    }
    if strings.Contains(res, "https://www.facebook.com/profile/pic.php") {
        return true
    } else {
        return false
    }
}