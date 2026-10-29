// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package kubesecrets

import "fmt"

// toStringMap converts map[string]interface{} to map[string]string.
// Returns an error if any value is not a string.
func toStringMap(raw interface{}) (map[string]string, error) {
	if raw == nil {
		return make(map[string]string), nil
	}
	rawMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map[string]interface{}, got %T", raw)
	}
	result := make(map[string]string, len(rawMap))
	for k, v := range rawMap {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("metadata value for key %q must be a string, got %T", k, v)
		}
		result[k] = s
	}
	return result, nil
}
