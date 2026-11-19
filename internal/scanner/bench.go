package scanner

import (
	"context"
	"math"
	"time"

	"anon-scan/internal/models"
)

func BenchmarkPort(ctx context.Context, ip string, port int, samples int, timeout time.Duration, proxyAddr string) models.BenchStats {
	stats := models.BenchStats{
		Port:    port,
		Samples: samples,
	}
	if samples <= 0 {
		return stats
	}

	var latencies []int64
	var sum int64

	for i := 0; i < samples; i++ {
		res := ProbePort(ctx, ip, port, timeout, proxyAddr)
		if res.Open {
			latencies = append(latencies, res.LatencyMS)
			sum += res.LatencyMS
		}
		if i < samples-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	succeeded := len(latencies)
	if succeeded == 0 {
		stats.LossPct = 100.0
		return stats
	}

	stats.LossPct = math.Round((float64(samples-succeeded)/float64(samples))*1000) / 10

	minVal := latencies[0]
	maxVal := latencies[0]
	for _, v := range latencies {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	stats.MinMS = minVal
	stats.MaxMS = maxVal
	stats.AvgMS = math.Round((float64(sum)/float64(succeeded))*10) / 10

	if succeeded > 1 {
		var diffSum float64
		for i := 1; i < succeeded; i++ {
			diffSum += math.Abs(float64(latencies[i] - latencies[i-1]))
		}
		stats.JitterMS = math.Round((diffSum/float64(succeeded-1))*10) / 10
	}

	return stats
}
