package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/0xPARC/parcnet/go/pod"
)

type PCDAddRequest struct {
	Type             string        `json:"type"`
	ReturnUrl        string        `json:"returnUrl"`
	Pcd              SerializedPCD `json:"pcd"`
	Folder           *string       `json:"folder,omitempty"`
	PostMessage      bool          `json:"postMessage"`
	RedirectToFolder *bool         `json:"redirectToFolder,omitempty"`
}

type SerializedPCD struct {
	Type string `json:"type"`
	Pcd  string `json:"pcd"`
}

func SerializePODPCD(id string, p pod.Pod) (*SerializedPCD, error) {
	payload := struct {
		ID      string   `json:"id"`
		JSONPOD pod.Pod  `json:"jsonPOD"`
	}{
		ID:      id,
		JSONPOD: p,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	return &SerializedPCD{
		Type: "pod-pcd",
		Pcd:  string(payloadBytes),
	}, nil
}

func createZupassAddRequestUrl(
	zupassClientUrl string,
	returnUrl string,
	pcd SerializedPCD,
	folder *string,
	postMessage bool,
	redirectToFolder *bool,
) (string, error) {

	req := PCDAddRequest{
		Type:             "Add",
		ReturnUrl:        returnUrl,
		Pcd:              pcd,
		PostMessage:      postMessage,
		Folder:           folder,
		RedirectToFolder: redirectToFolder,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal PCDAddRequest: %w", err)
	}

	encodedReq := url.QueryEscape(string(reqBytes))

	finalURL := fmt.Sprintf("%s#/add?request=%s", zupassClientUrl, encodedReq)
	return finalURL, nil
}