package writers

import "github.com/cmprmsd/gowitness/pkg/models"

// Writer is a results writer
type Writer interface {
	Write(*models.Result) error
}
