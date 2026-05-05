package api

import (
	"encoding/json"
	"net/http"

	"github.com/cmprmsd/gowitness/pkg/log"
	"github.com/cmprmsd/gowitness/pkg/models"
)

// tagListEntry is one (value, type) pair for the tag dropdown. Type is
// "name", "category", "vendor", or "" for legacy rows scanned before
// the type field was introduced. Lets the UI group the dropdown.
type tagListEntry struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type tagListResponse struct {
	Tags []tagListEntry `json:"tags"`
}

// TagListHandler lists tags
//
//	@Summary		Get tag results
//	@Description	Get all the unique tags detected by the favicon-hash + YAML tagger, with their classification axis.
//	@Tags			Results
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	tagListResponse
//	@Router			/results/tag [get]
func (h *ApiHandler) TagListHandler(w http.ResponseWriter, r *http.Request) {
	var results = &tagListResponse{Tags: []tagListEntry{}}

	if err := h.DB.Model(&models.Tag{}).
		Select("value, type").
		Distinct("value", "type").
		Order("type").Order("value").
		Find(&results.Tags).Error; err != nil {

		log.Error("could not find distinct tags", "err", err)
		return
	}

	jsonData, err := json.Marshal(results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(jsonData)
}
