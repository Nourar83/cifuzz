package api

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

type ProjectBody struct {
	Project Project `json:"project"`
}

type Project struct {
	Name                  string `json:"name"`
	DisplayName           string `json:"display_name"`
	OwnerOrganizationName string `json:"owner_organization_name,omitempty"`
}

type ProjectResponse struct {
	Name     string   `json:"name"`
	Done     bool     `json:"done"`
	Response Response `json:"response"`
}

type Response struct {
	Type          string   `json:"@type"`
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	Location      Location `json:"location"`
	OwnerUsername string   `json:"owner_username"`
}

type Location struct {
	GitPath GitPath `json:"git_path"`
}

type GitPath struct{}

func (client *APIClient) ListProjects(token string) ([]*Project, error) {
	resp, err := client.sendRequest("GET", "v1/projects", nil, token)
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

func (client *APIClient) CreateProject(name string, token string) (*Project, error) {
	projectBody := &ProjectBody{
		Project: Project{
			DisplayName: name,
		},
	}

	body, err := json.Marshal(projectBody)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := client.sendRequest("POST", "v1/projects", bytes.NewReader(body), token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, responseToAPIError(resp)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var projectResponse ProjectResponse
	err = json.Unmarshal(body, &projectResponse)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	projectBody.Project.Name = projectResponse.Response.Name

	return &projectBody.Project, nil
}
