package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"sort"
	"strconv"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

func parseJSON(jsonData string) ([]Point, int, error) {
	// First parse into a generic map to handle the mixed structure
	var rawData map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &rawData)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Extract keys - handle both object and direct access
	var k int
	if keysData, ok := rawData["keys"].(map[string]interface{}); ok {
		if kVal, ok := keysData["k"].(float64); ok {
			k = int(kVal)
		} else {
			return nil, 0, fmt.Errorf("k value not found or invalid type")
		}
	} else {
		return nil, 0, fmt.Errorf("keys field not found or invalid")
	}

	var points []Point
	for key, value := range rawData {
		if key == "keys" {
			continue
		}

		// Parse the key as x coordinate - must be valid integer
		x, err := strconv.Atoi(key)
		if err != nil {
			continue // Skip invalid keys
		}

		// x must be positive for Shamir's Secret Sharing
		if x <= 0 {
			continue
		}

		// Parse the root data
		rootMap, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		baseStr, ok := rootMap["base"].(string)
		if !ok {
			return nil, 0, fmt.Errorf("invalid base for key %s", key)
		}

		valueStr, ok := rootMap["value"].(string)
		if !ok {
			return nil, 0, fmt.Errorf("invalid value for key %s", key)
		}

		// Validate base
		base, err := strconv.Atoi(baseStr)
		if err != nil || base < 2 || base > 36 {
			return nil, 0, fmt.Errorf("invalid base for key %s: %s (must be 2-36)", key, baseStr)
		}

		// Validate and parse value
		if valueStr == "" {
			return nil, 0, fmt.Errorf("empty value for key %s", key)
		}

		y := big.NewInt(0)
		y, ok = y.SetString(valueStr, base)
		if !ok {
			return nil, 0, fmt.Errorf("invalid value for key %s: %s in base %d", key, valueStr, base)
		}

		// Check for negative values (shouldn't happen in valid secret sharing)
		if y.Sign() < 0 {
			return nil, 0, fmt.Errorf("negative value for key %s: %s", key, y.String())
		}

		points = append(points, Point{
			X: big.NewInt(int64(x)),
			Y: y,
		})
	}

	// Sort points by X coordinate to ensure consistent ordering
	sort.Slice(points, func(i, j int) bool {
		return points[i].X.Cmp(points[j].X) < 0
	})

	// Check for duplicate X values
	for i := 1; i < len(points); i++ {
		if points[i].X.Cmp(points[i-1].X) == 0 {
			return nil, 0, fmt.Errorf("duplicate x coordinate: %s", points[i].X.String())
		}
	}

	return points, k, nil
}

func lagrangeInterpolation(points []Point, k int) *big.Int {
	if len(points) < k {
		return nil
	}

	selectedPoints := points[:k]

	// Use rational arithmetic for exact computation
	result := big.NewRat(0, 1)

	for i := 0; i < len(selectedPoints); i++ {
		// Calculate Lagrange basis polynomial L_i(0)
		numerator := big.NewRat(1, 1)
		denominator := big.NewRat(1, 1)

		for j := 0; j < len(selectedPoints); j++ {
			if i != j {
				// For L_i(0), we want (0 - x_j) / (x_i - x_j)

				// Numerator: multiply by (0 - x_j) = -x_j
				xj := big.NewRat(0, 1)
				xj.SetInt(selectedPoints[j].X)
				xj.Neg(xj)
				numerator.Mul(numerator, xj)

				// Denominator: multiply by (x_i - x_j)
				xi := big.NewRat(0, 1)
				xi.SetInt(selectedPoints[i].X)
				xj = big.NewRat(0, 1)
				xj.SetInt(selectedPoints[j].X)
				diff := big.NewRat(0, 1)
				diff.Sub(xi, xj)

				// Check for zero difference (duplicate points)
				if diff.Sign() == 0 {
					return nil
				}

				denominator.Mul(denominator, diff)
			}
		}

		// Check for zero denominator
		if denominator.Sign() == 0 {
			return nil
		}

		// Calculate the Lagrange basis value L_i(0)
		basisValue := big.NewRat(0, 1)
		basisValue.Quo(numerator, denominator)

		// Multiply by y_i and add to result
		yi := big.NewRat(0, 1)
		yi.SetInt(selectedPoints[i].Y)
		term := big.NewRat(0, 1)
		term.Mul(yi, basisValue)
		result.Add(result, term)
	}

	// Convert rational result back to integer
	// The result should be an exact integer for valid Shamir's Secret Sharing
	if !result.IsInt() {
		// This shouldn't happen with valid secret sharing, but handle it gracefully
		return nil
	}

	return result.Num()
}

func solveSecretSharing(jsonData string) (*big.Int, error) {
	points, k, err := parseJSON(jsonData)
	if err != nil {
		return nil, err
	}

	if k <= 0 {
		return nil, fmt.Errorf("invalid k value: %d (must be positive)", k)
	}

	if len(points) < k {
		return nil, fmt.Errorf("insufficient points: need %d, got %d", k, len(points))
	}

	secret := lagrangeInterpolation(points, k)
	if secret == nil {
		return nil, fmt.Errorf("failed to interpolate polynomial")
	}

	return secret, nil
}

func readJSONFile(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filename, err)
	}
	return data, nil
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}

	filename := os.Args[1]

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		os.Exit(1)
	}

	jsonData, err := readJSONFile(filename)
	if err != nil {
		os.Exit(1)
	}

	if len(jsonData) == 0 {
		os.Exit(1)
	}

	secret, err := solveSecretSharing(string(jsonData))
	if err != nil {
		os.Exit(1)
	}

	fmt.Println(secret.String())
}
