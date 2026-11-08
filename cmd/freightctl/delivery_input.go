package main

import (
	"io"

	"github.com/ctlplne/freightctl/internal/delivery"
)

func decodeDeliveryRequest(input io.Reader) (delivery.Request, error) {
	var request delivery.Request
	err := decodeCLIControl(input, &request, 16<<10)
	return request, err
}
