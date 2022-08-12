/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"

	"github.com/cfreemoser/subdomain_guesser/service"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// guessCmd represents the guess command
var guessCmd = &cobra.Command{
	Use:   "guess",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: exec,
}

var (
	domain    string
	wordList  string
	maxWorker int64
	dnsServer string

	//go:embed data/all.txt
	data []byte
)

func init() {
	rootCmd.AddCommand(guessCmd)

	guessCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "The domain to perform guessing against")
	guessCmd.MarkFlagRequired("domain")

	guessCmd.PersistentFlags().StringVarP(&wordList, "word-list", "w", "", "The wordlist to use for guessing")

	guessCmd.PersistentFlags().Int64VarP(&maxWorker, "max-worker", "m", 1000, "The maximum amount of workers to use")

	guessCmd.PersistentFlags().StringVar(&dnsServer, "dns-server", "8.8.8.8:53", "DNS server to be used")
}

func exec(cmd *cobra.Command, args []string) error {
	var results []service.Result
	fqdns := make(chan string, maxWorker)
	gather := make(chan []service.Result)
	tracker := make(chan empty)
	table := tablewriter.NewWriter(cmd.OutOrStdout())
	table.SetHeader([]string{"RECORD", "IP"})

	// start all worker
	for i := 0; i < int(maxWorker); i++ {
		go worker(tracker, fqdns, gather, dnsServer)
	}

	// start collector
	go func() {
		for r := range gather {
			for _, v := range r {
				table.Append([]string{v.Hostname, v.IPAddress})
			}
			results = append(results, r...)
		}
		var e empty
		tracker <- e
	}()

	// read worklist
	var reader io.Reader
	if len(wordList) > 0 {
		fh, err := os.Open(wordList)
		if err != nil {
			return fmt.Errorf("could not open file %s error: %w", wordList, err)
		}
		defer fh.Close()
		reader = fh
	} else {
		reader = bytes.NewReader(data)
	}

	// send work and close send channel afterwards
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fqdns <- fmt.Sprintf("%s.%s", scanner.Text(), domain)
	}
	close(fqdns)

	// wait for all worker to complete
	for i := 0; i < int(maxWorker); i++ {
		<-tracker
	}

	close(gather)
	<-tracker
	close(tracker)

	table.Render()
	return nil
}

type empty struct{}

func worker(tracker chan<- empty, fqdns <-chan string, gather chan<- []service.Result, serverAddr string) {
	for fqdn := range fqdns {
		results := service.Lookup(fqdn, serverAddr)
		if len(results) > 0 {
			gather <- results
		}
	}
	var e empty
	tracker <- e
}
