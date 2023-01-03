package daemon

import "math"






// Implementing dynamic scoring function https://github.com/sigpwny/ctfd-dynamic-challenges-mod/blob/main/__init__.py
const (
	p0 = 0.7
	p1 = 0.96
)

var (
	c0 = -math.Atanh(p0)
	c1 = math.Atanh(p1)
)

func dynA(solves float64) float64 {
	return (1 - math.Tanh(solves)) / 2
}

func dynB(solves float64) float64 {
	return (dynA((c1-c0)*solves+c0) - dynA(c1)) / (dynA(c0) - dynA(c1))
}

func getScore(eventConf EventConfig, solves int) int {
	s := math.Max(1, float64(eventConf.DynamicSolveThreshold))
	f := func(solves float64) float64 {
		return float64(eventConf.DynamicMin) + (float64(eventConf.DynamicMax)-float64(eventConf.DynamicMin))*dynB(solves/s)
	}
	return int(math.Round(math.Max(f(float64(solves)), f(s))))
}
