package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-co-op/gocron"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/urfave/cli"
)

var (
	wg sync.WaitGroup
)

type rvisionString struct {
	Value     string `json:"Value"`
	ValueType string `json:"Type"`
}

type kpsnRequest struct {
	Action string   `json:"action"`
	Data   kpsnData `json:"data"`
}

type kpsnDelRequest struct {
	Action string      `json:"action"`
	Data   kpsnDelData `json:"data"`
}

type kpsnData struct {
	Force    bool           `json:"force"`
	HashType string         `json:"hash_type"`
	Urls     []kpsnDataUrls `json:"urls"`
	Hashes   []kpsnDataFile `json:"hashes"`
}

type kpsnDelData struct {
	Force    bool     `json:"force"`
	HashType string   `json:"hash_type"`
	Urls     []string `json:"urls"`
	Hashes   []string `json:"hashes"`
}

type kpsnDataUrls struct {
	URL         string `json:"url"`
	Verdict     int    `json:"verdict"`
	Description string `json:"description"`
}

type kpsnDataFile struct {
	Hash        string `json:"hash"`
	Verdict     int    `json:"verdict"`
	FileName    string `json:"file_name"`
	Description string `json:"description"`
}

type kpsnError struct {
	ErrorСode int    `json:"error_code"`
	ErrorText string `json:"error_text"`
	Hash      string `json:"hash"`
}

type kpsnResponse struct {
	Data []kpsnError `json:"data"`
}

type allIocs struct {
	Md5    []string `json:"md5"`
	Sha256 []string `json:"sha256"`
	Urls   []string `json:"urls"`
}

type httpRequest struct {
	URL            string
	method         string
	data           []byte
	clientCertPath string
	clientKeyPath  string
	timeout        int
	contentType    string
}

func (request httpRequest) Do() (responseData []byte, err error) {

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
	}

	if len(request.clientCertPath) != 0 && len(request.clientKeyPath) != 0 {
		// Load client cert
		cert, err := tls.LoadX509KeyPair(request.clientCertPath, request.clientKeyPath)
		if err != nil {
			return responseData, err
		}

		log.Debugln("Client certificate and key have been uploaded")

		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.BuildNameToCertificate()

	}

	// Create client
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * time.Duration(request.timeout),
	}

	log.Debugln("Initialization of http client completed")

	// Send request
	log.Debugf("Sending http request, method: %s, URL: %s, data: %s, content-type: %s", request.method, request.URL, request.data, request.contentType)
	req, err := http.NewRequest(request.method, request.URL, bytes.NewBuffer(request.data))
	if err != nil {
		return responseData, err
	}

	req.Header.Set("content-type", request.contentType)

	resp, err := client.Do(req)
	if err != nil {
		return responseData, err
	}

	log.Debugln("Http request has been sent, method: %s, URL: %s, data: %s, content-type: %s", request.method, request.URL, request.data, request.contentType)

	// Get response
	defer resp.Body.Close()
	responseData, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return responseData, err
	}

	log.Debugf("Received response from http request: %s", responseData)

	// Check Status Code
	if resp.StatusCode != 200 {
		return responseData, fmt.Errorf("Connection to URL: %s ended with error: %s", request.URL, resp.Status)
	}

	return responseData, nil
}

type kpsn struct {
	URL      string
	data     []byte
	certPath string
	keyPath  string
	timeout  int
	force    bool
}

func (k kpsn) SendRequest() (responseData []byte, err error) {

	var (
		errorKpsn    kpsnError
		responseKpsn kpsnResponse
	)

	jsonReq := json.RawMessage(k.data)
	if err != nil {
		return responseData, err
	}

	request := httpRequest{
		URL:            k.URL,
		method:         "POST",
		data:           jsonReq,
		clientCertPath: k.certPath,
		clientKeyPath:  k.keyPath,
		timeout:        k.timeout,
		contentType:    "application/json",
	}

	responseData, err = request.Do()
	if err != nil {
		return responseData, err
	}

	json.Unmarshal(responseData, &errorKpsn)
	if errorKpsn.ErrorСode != 0 {
		return responseData, fmt.Errorf("KPSN return error, code: %d, message: %s", errorKpsn.ErrorСode, errorKpsn.ErrorText)
	}

	json.Unmarshal(responseData, &responseKpsn)
	for _, errorKpsn = range responseKpsn.Data {
		if errorKpsn.ErrorСode != 0 {
			return responseData, fmt.Errorf("KPSN return error, hash: %s, code: %d, message: %s", errorKpsn.Hash, errorKpsn.ErrorСode, errorKpsn.ErrorText)
		}
	}

	return responseData, nil
}

type rvision struct {
	URL     string
	timeout int
}

func (r rvision) SendRequest() (responseData []byte, err error) {

	request := httpRequest{
		URL:         r.URL,
		method:      "GET",
		timeout:     r.timeout,
		contentType: "application/json",
	}

	responseData, err = request.Do()
	if err != nil {
		return responseData, err
	}

	return responseData, nil
}

type iocProperties struct {
	action     string
	objectType string
}

func getOldData(tmpFilePath string) (md5 []string, sha256 []string, urls []string, err error) {
	var (
		oldJSONFile *os.File
		oldJSON     allIocs
	)

	if _, err := os.Stat(tmpFilePath); err == nil {
		oldJSONFile, err = os.Open(tmpFilePath)
		if err != nil {
			return md5, sha256, urls, err
		}

		log.Debugf("Received old data from file %s", tmpFilePath)

		byteValue, _ := ioutil.ReadAll(oldJSONFile)
		json.Unmarshal(byteValue, &oldJSON)
		md5 = oldJSON.Md5
		sha256 = oldJSON.Sha256
		urls = oldJSON.Urls
		return md5, sha256, urls, nil
	}

	return md5, sha256, urls, err

}

func compareIoCs(old []string, new []string) (addResult []string, delResult []string) {

	oldMap := make(map[string]struct{}, len(old))
	for _, n := range old {
		oldMap[n] = struct{}{}
	}
	for _, n := range new {
		if _, ok := oldMap[n]; !ok {
			addResult = append(addResult, n)
		}
	}

	newMap := make(map[string]struct{}, len(new))
	for _, n := range new {
		newMap[n] = struct{}{}
	}
	for _, n := range old {
		if _, ok := newMap[n]; !ok {
			delResult = append(delResult, n)
		}
	}

	return addResult, delResult
}

func separationIoC(iocs []rvisionString) (md5 []string, sha256 []string, urls []string) {

	for _, ioc := range iocs {
		if ioc.ValueType == "md5" {
			md5 = append(md5, ioc.Value)
		}
		if ioc.ValueType == "sha256" {
			sha256 = append(sha256, ioc.Value)
		}
		if ioc.ValueType == "url" || ioc.ValueType == "domain" {
			urls = append(urls, ioc.Value)
		}
	}

	return md5, sha256, urls
}

func preparatIocs(iocs []string, action string, objectType string, force bool) (byteData []byte, err error) {

	if len(iocs) != 0 {
		if action == "add" {

			data := kpsnRequest{
				Data: kpsnData{
					Force: force,
				},
			}

			if objectType == "md5" || objectType == "sha256" {

				var (
					hashes []kpsnDataFile
				)

				for _, ioc := range iocs {
					hash := kpsnDataFile{
						Hash:        ioc,
						Verdict:     2,
						FileName:    ioc,
						Description: "RVision",
					}
					hashes = append(hashes, hash)
				}

				data.Action = "add_file"
				data.Data.Hashes = hashes
				data.Data.HashType = objectType

			} else if objectType == "url" {

				var (
					urls []kpsnDataUrls
				)

				for _, ioc := range iocs {
					url := kpsnDataUrls{
						URL:         ioc,
						Verdict:     2,
						Description: "RVision",
					}
					urls = append(urls, url)
				}

				data.Action = "add_url"
				data.Data.Urls = urls
			}

			byteData, err = json.Marshal(data)
			if err != nil {
				return byteData, err
			}

		} else if action == "delete" {

			data := kpsnDelRequest{
				Data: kpsnDelData{
					Force: force,
				},
			}

			if objectType == "md5" || objectType == "sha256" {

				var (
					hashes []string
				)

				for _, ioc := range iocs {
					hashes = append(hashes, ioc)
				}

				data.Action = "delete_file"
				data.Data.Hashes = hashes
				data.Data.HashType = objectType

			} else if objectType == "url" {

				var (
					urls []string
				)

				for _, ioc := range iocs {
					urls = append(urls, ioc)
				}

				data.Action = "delete_url"
				data.Data.Urls = urls

			}

			byteData, err = json.Marshal(data)
			if err != nil {
				return byteData, err
			}

		}
	}

	return byteData, nil
}

func addReputationToKPSN(kpsnServer kpsn, iocsSeparatedBySize []string, prop iocProperties, c chan error, goroutines chan struct{}) {
	defer wg.Done()
	byteData, err := preparatIocs(iocsSeparatedBySize, prop.action, prop.objectType, kpsnServer.force)
	if err != nil {
		c <- err
	}
	if len(byteData) != 0 {
		kpsnServer.data = byteData
		_, err := kpsnServer.SendRequest()
		if err != nil {
			c <- err
		}
	}
	<-goroutines
}

func errorHandler(c chan error) {
	for {
		err := <-c
		log.Errorln(err)
		time.Sleep(1)
	}
}

func cliMenu() (configPath string, logPath string, err error) {

	app := &cli.App{
		Name:     "KPSN - RVision Integration",
		Version:  "v1.0",
		Compiled: time.Now(),
		Action: func(c *cli.Context) error {
			log.Debugln("Starting application...")
			return nil
		},
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "config",
			Usage:       "Load configuration from `FILE` - required",
			Destination: &configPath,
			Required:    true,
			Aliases:     []string{"c"},
		},
		&cli.StringFlag{
			Name:        "log",
			Usage:       "Save log to `FILE` - required",
			Destination: &logPath,
			Required:    true,
			Aliases:     []string{"l"},
		},
	}

	app.Authors = []*cli.Author{
		{
			Name:  "Mikhail Steblin"
		},
	}

	app.Copyright = "(c) 2020 Mikhail Steblin"

	cli.AppHelpTemplate = `
{{.Name}} {{.Version}}
	{{if len .Authors}}
AUTHOR:
	{{range .Authors}}{{ . }}{{end}}{{end}}

USAGE:
	{{.HelpName}} {{if .VisibleFlags}}[options]{{end}}

OPTIONS:
	{{range .VisibleFlags}}{{.}}
	{{end}}{{if .Copyright }}

{{.Copyright}}
{{end}}
`

	err = app.Run(os.Args)
	if err != nil {
		return configPath, logPath, err
	}

	return configPath, logPath, nil
}

func sendIocsFromRvisionToKpsn(kpsnServer kpsn, rvisionServer rvision, tmpPath string) {
	var (
		rvisionIocs []rvisionString
		c           chan error = make(chan error)
	)

	goroutines := make(chan struct{}, 15)

	iocsForAction := make(map[iocProperties][]string)

	rvisionByteIocs, err := rvisionServer.SendRequest()
	if err != nil {
		log.Errorln(err)
		return
	}
	json.Unmarshal(rvisionByteIocs, &rvisionIocs)

	newMd5, newSha256, newUrls := separationIoC(rvisionIocs)
	oldMd5, oldSha256, oldUrls, err := getOldData(tmpPath)
	if err != nil {
		log.Errorln(err)
	}

	iocsForAction[iocProperties{"add", "md5"}], iocsForAction[iocProperties{"delete", "md5"}] = compareIoCs(oldMd5, newMd5)
	iocsForAction[iocProperties{"add", "sha256"}], iocsForAction[iocProperties{"delete", "sha256"}] = compareIoCs(oldSha256, newSha256)
	iocsForAction[iocProperties{"add", "url"}], iocsForAction[iocProperties{"delete", "url"}] = compareIoCs(oldUrls, newUrls)

	change := false

	if len(iocsForAction) != 0 {
		go errorHandler(c)
		for prop, iocs := range iocsForAction {
			var iocsSeparatedBySize []string

			size := 0
			maxSize := 128*1024 - 300
			iocSize := 0

			switch prop.objectType {
			case "md5":
				iocSize = 151
			case "sha256":
				iocSize = 215
			}
			if len(iocs) != 0 {
				change = true
				for _, ioc := range iocs {
					if prop.objectType == "url" {
						iocSize = len(ioc) + 110
					}

					if size+iocSize < maxSize {
						size = size + iocSize
						iocsSeparatedBySize = append(iocsSeparatedBySize, ioc)
					} else {
						goroutines <- struct{}{}
						wg.Add(1)
						go addReputationToKPSN(kpsnServer, iocsSeparatedBySize, prop, c, goroutines)
						size = 0
						iocsSeparatedBySize = nil
						iocsSeparatedBySize = append(iocsSeparatedBySize, ioc)
					}
				}
			}
			if change == true {
				goroutines <- struct{}{}
				wg.Add(1)
				go addReputationToKPSN(kpsnServer, iocsSeparatedBySize, prop, c, goroutines)
			}
		}
	} else {
		log.Debug("Incorrect format struct 'iocsForAction'")
	}

	if change == false {
		log.Debug("No changes. No action required")
	}

	saveJSON, _ := json.Marshal(allIocs{newMd5, newSha256, newUrls})
	err = ioutil.WriteFile(tmpPath, saveJSON, 0644)
	if err != nil {
		log.Errorln(err)
	}

	wg.Wait()
	close(goroutines)

}

func main() {

	// run cli menu and get settings from keys
	configPath, logPath, err := cliMenu()
	if err != nil {
		os.Exit(0)
	}

	// set logging settings
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Unable create log file: %s", err)
	} else {
		log.SetOutput(logFile)
	}

	formatter := new(log.TextFormatter)
	formatter.FullTimestamp = true

	// read configuration file and get setting from configuration file
	viper.SetConfigFile(configPath)
	viper.SetConfigType("toml")
	err = viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Unable to read config file: %s", err)
	}

	rvisionURL := viper.GetString("rvision_url")
	kpsnURL := viper.GetString("kpsn_url")
	pathToKpsnCert := viper.GetString("path_to_client_cert")
	pathToKpsnKey := viper.GetString("path_to_client_key")
	forceKPSN := viper.GetBool("kpsn_force")
	tmpPath := viper.GetString("tmp_path")
	timeoutT := viper.GetInt("connection_timeout")
	serviceTimeout := viper.GetInt("service_timeout")
	logLevel := viper.GetString("log_level")

	switch logLevel {
	case "ERR":
		log.SetLevel(log.ErrorLevel)
	case "DBG":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	log.Debugf("Received settings from the configuration file: %s", configPath)

	// Initialize KPSN and RVision servers

	kpsnServer := kpsn{
		URL:      kpsnURL,
		certPath: pathToKpsnCert,
		keyPath:  pathToKpsnKey,
		timeout:  timeoutT,
		force:    forceKPSN,
	}

	log.Debugf("KPSN server initialized with parameters: URL: %s, Force: %b, Timeout: %d, KeyPath: %s, CertPath: %s", kpsnServer.URL, kpsnServer.force, kpsnServer.timeout, kpsnServer.keyPath, kpsnServer.certPath)

	rvisionServer := rvision{
		URL:     rvisionURL,
		timeout: timeoutT,
	}

	log.Debugf("RVision server initialized with parameters: URL: %s, Timeout: %d", rvisionServer.URL, rvisionServer.timeout)

	// send IOCs from RVision to KPSN
	goCronScheduler := gocron.NewScheduler(time.UTC)

	_, err = goCronScheduler.Every(uint64(serviceTimeout)).Minutes().Do(sendIocsFromRvisionToKpsn, kpsnServer, rvisionServer, tmpPath)
	if err != nil {
		log.Fatalf("Don't create cron jobs with error: %s", err)
	}

	goCronScheduler.StartBlocking()

}
