package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
	"golang.org/x/net/proxy"

	"code-intelligence.com/cifuzz/internal/cmd/remote-run/progress"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/stringutil"
)

// APIError is returned when a REST request returns a status code other
// than 200 OK
type APIError struct {
	err        error
	StatusCode int
}

func (e APIError) Error() string {
	return e.err.Error()
}

func (e APIError) Format(s fmt.State, verb rune) {
	if formatter, ok := e.err.(fmt.Formatter); ok {
		formatter.Format(s, verb)
	} else {
		_, _ = io.WriteString(s, e.Error())
	}
}

func (e APIError) Unwrap() error {
	return e.err
}

func responseToAPIError(resp *http.Response) error {
	msg := resp.Status
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &APIError{StatusCode: resp.StatusCode, err: errors.New(msg)}
	}
	apiResp := struct {
		Code    int
		Message string
	}{}
	err = json.Unmarshal(body, &apiResp)
	if err != nil {
		return &APIError{StatusCode: resp.StatusCode, err: errors.Errorf("%s: %s", msg, string(body))}
	}
	return &APIError{StatusCode: resp.StatusCode, err: errors.Errorf("%s: %s", msg, apiResp.Message)}
}

type APIClient struct {
	Server string
}

var FeaturedProjectsOrganization = "organizations/1"

type Project struct {
	Name                  string `json:"name"`
	DisplayName           string `json:"display_name"`
	OwnerOrganizationName string `json:"owner_organization_name"`
}

type Artifact struct {
	DisplayName  string `json:"display-name"`
	ResourceName string `json:"resource-name"`
}

func (client *APIClient) UploadBundle(path string, projectName string, token string) (*Artifact, error) {
	signalHandlerCtx, cancelSignalHandler := context.WithCancel(context.Background())
	routines, routinesCtx := errgroup.WithContext(context.Background())

	// Cancel the routines context when receiving a termination signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	routines.Go(func() error {
		select {
		case <-signalHandlerCtx.Done():
			return nil
		case s := <-sigs:
			log.Warnf("Received %s", s.String())
			return cmdutils.NewSignalError(s.(syscall.Signal))
		}
	})

	// Use a pipe to avoid reading the artifacts into memory at once
	r, w := io.Pipe()
	m := multipart.NewWriter(w)

	// Write the artifacts to the pipe
	routines.Go(func() error {
		defer w.Close()
		defer m.Close()

		part, err := m.CreateFormFile("fuzzing-artifacts", path)
		if err != nil {
			return errors.WithStack(err)
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return errors.WithStack(err)
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.WithStack(err)
		}
		defer f.Close()

		var reader io.Reader
		printProgress := term.IsTerminal(int(os.Stdout.Fd()))
		if printProgress {
			fmt.Println("Uploading...")
			reader = progress.NewReader(f, fileInfo.Size(), "Upload complete")
		} else {
			reader = f
		}

		_, err = io.Copy(part, reader)
		return errors.WithStack(err)
	})

	// Send a POST request with what we read from the pipe. The request
	// gets cancelled with the routines context is cancelled, which
	// happens if an error occurs in the io.Copy above or the user if
	// cancels the operation.
	var body []byte
	routines.Go(func() error {
		defer r.Close()
		defer cancelSignalHandler()
		url := fmt.Sprintf("%s/v2/%s/artifacts/import", client.Server, projectName)
		req, err := http.NewRequestWithContext(routinesCtx, "POST", url, r)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Header.Set("Content-Type", m.FormDataContentType())
		req.Header.Add("Authorization", "Bearer "+token)

		httpClient := &http.Client{Transport: GetCustTransportLayer()}
		resp, err := httpClient.Do(req)
		if err != nil {
			return errors.WithStack(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return responseToAPIError(resp)
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})

	err := routines.Wait()
	if err != nil {
		return nil, err
	}

	artifact := &Artifact{}
	err = json.Unmarshal(body, artifact)
	if err != nil {
		err = errors.WithStack(err)
		log.Errorf(err, "Failed to parse response from upload bundle API call: %s", err.Error())
		return nil, cmdutils.WrapSilentError(err)
	}

	return artifact, nil
}

func (client *APIClient) StartRemoteFuzzingRun(artifact *Artifact, token string) (string, error) {
	resp, err := client.sendRequest("POST", fmt.Sprintf("v1/%s:run", artifact.ResourceName), token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", responseToAPIError(resp)
	}

	// Get the campaign run name from the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return "", errors.WithStack(err)
	}
	campaignRunNameJSON, ok := objmap["name"]
	if !ok {
		err := errors.Errorf("Server response doesn't include run name: %v", stringutil.PrettyString(objmap))
		log.Error(err)
		return "", cmdutils.WrapSilentError(err)
	}
	var campaignRunName string
	err = json.Unmarshal(campaignRunNameJSON, &campaignRunName)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return campaignRunName, nil
}

func (client *APIClient) sendRequest(method, endpoint, token string) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", client.Server, endpoint)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Add("Authorization", "Bearer "+token)

	httpClient := &http.Client{Transport: GetCustTransportLayer()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return resp, nil
}

func (client *APIClient) ListProjects(token string) ([]*Project, error) {
	resp, err := client.sendRequest("GET", "v1/projects", token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, responseToAPIError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var projects []*Project
	err = json.Unmarshal(objmap["projects"], &projects)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Filter out featured projects
	var filteredProjects []*Project
	for _, p := range projects {
		if p.OwnerOrganizationName == FeaturedProjectsOrganization {
			continue
		}
		filteredProjects = append(filteredProjects, p)
	}

	return filteredProjects, nil
}

func (client *APIClient) IsTokenValid(token string) (bool, error) {
	// TOOD: Change this to use another check without querying projects
	_, err := client.ListProjects(token)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == 401 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func ValidateURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return errors.WithStack(err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.Errorf("unsupported protocol scheme %q", u.Scheme)
	}
	return nil
}

func GetCustTransportLayer() *http.Transport {
	dialer := proxy.FromEnvironment()
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}
	return &http.Transport{DialContext: dialContext, DisableKeepAlives: true}
}
